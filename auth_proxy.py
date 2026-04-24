"""OpenHost auth proxy sidecar for Miniflux.

Sits between the OpenHost router and Miniflux. Verifies the visitor's
`zone_auth` JWT cookie (signed by the OpenHost router with RS256, published
at /.well-known/jwks.json on the router) and, when the claim `sub == "owner"`,
stamps an `X-Openhost-User: admin` header on the proxied request.

Miniflux is configured with AUTH_PROXY_HEADER=X-Openhost-User, so a valid
stamped header authenticates the owner as the `admin` Miniflux user. On the
first such request, Miniflux auto-creates the admin account
(AUTH_PROXY_USER_CREATION=1). DISABLE_LOCAL_AUTH=1 hides the password form.

Why not trust `X-OpenHost-Is-Owner`? The OpenHost router passes client-supplied
headers through to apps on public paths and overwrites X-OpenHost-Is-Owner only
for authenticated owners. Non-owner visitors to a public path could forge the
header. Miniflux exposes no public paths today, so the header would be usable
in this app, but we mirror the mirotalk pattern — verify a signed JWT ourselves
— so the app stays safe even if routing behavior changes or a `public_paths`
entry is added later.

We deliberately strip any incoming X-Openhost-User header on every request so
that a hostile upstream or client cannot inject auth by setting it themselves.
Miniflux's TRUSTED_REVERSE_PROXY_NETWORKS is also set to 127.0.0.1/32 so only
this sidecar's stamped header is honored.
"""

from __future__ import annotations

import http.client
import logging
import os
import socket
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterable

import jwt
import requests

AUTH_HEADER_NAME = "X-Openhost-User"
ZONE_COOKIE = "zone_auth"
JWKS_PATH = "/.well-known/jwks.json"
JWKS_REFRESH_INTERVAL_SEC = 600  # 10 minutes
# Headers that must not be forwarded hop-by-hop (RFC 7230 §6.1) plus a few
# extras where we control the forwarding meaning.
HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        # Host is rewritten by the http.client layer based on the target.
        "Host",
        # We rewrite these to reflect our own connection.
        "Content-Length",
    )
)

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


class JwksCache:
    """Fetches the OpenHost router's JWKS and caches it with stale fallback.

    Mirrors the pattern used by openhost-mirotalk-p2p/openhost-shim.js: on
    a successful fetch the keys are cached for JWKS_REFRESH_INTERVAL_SEC; on
    a failed refresh we keep serving the previously-cached keys rather than
    failing closed, so a transient router outage doesn't lock the owner out.
    """

    def __init__(self, router_url: str) -> None:
        self._router_url = router_url.rstrip("/")
        self._keys: list = []
        self._fetched_at: float = 0.0
        self._lock = threading.Lock()

    def _fetch(self) -> list:
        url = f"{self._router_url}{JWKS_PATH}"
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        jwks = resp.json()
        keys = []
        for jwk in jwks.get("keys", []):
            # PyJWT expects an algorithms object; derive from the JWK.
            key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
            keys.append(key)
        if not keys:
            raise RuntimeError("router JWKS contains no keys")
        return keys

    def get(self) -> list:
        with self._lock:
            if self._keys and (time.time() - self._fetched_at) < JWKS_REFRESH_INTERVAL_SEC:
                return self._keys
            try:
                keys = self._fetch()
                self._keys = keys
                self._fetched_at = time.time()
                log.info("refreshed JWKS (%d key(s))", len(keys))
            except Exception as exc:  # noqa: BLE001 - we want to log+fallback
                if self._keys:
                    log.warning(
                        "JWKS refresh failed, using cached keys: %s", exc
                    )
                else:
                    log.warning("JWKS fetch failed and no cache: %s", exc)
                    raise
            return self._keys

    def prefetch(self) -> None:
        try:
            self.get()
        except Exception as exc:  # noqa: BLE001
            log.warning("initial JWKS prefetch failed (will retry on demand): %s", exc)


def _parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    """Parse an RFC6265 Cookie header into a {name: value} dict.

    Purposefully lenient: cookies with malformed encoding are stored as-is;
    JWT values only contain URL-safe base64 characters + two dots so decoding
    is a no-op in practice.
    """
    if not cookie_header:
        return {}
    result: dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        result[name.strip()] = value.strip()
    return result


def _verify_owner(token: str, jwks: JwksCache) -> bool:
    """Return True if the JWT is a valid router-signed owner token."""
    if not token:
        return False
    try:
        keys = jwks.get()
    except Exception:  # noqa: BLE001
        # No keys available and nothing cached. Fail closed.
        return False

    # Try each key; RS256 verification, require exp claim, no audience check
    # (the router doesn't set aud). If any key verifies, accept.
    for key in keys:
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                options={
                    "require": ["exp"],
                    "verify_aud": False,
                },
            )
        except jwt.PyJWTError:
            continue
        if claims.get("sub") == "owner":
            return True
        # A valid but non-owner token (e.g. future guest tokens) - treat as
        # unauthenticated for our purposes.
        return False
    return False


def _strip_headers(headers: Iterable[tuple[str, str]], drop: set[str]) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


class AuthProxyHandler(BaseHTTPRequestHandler):
    jwks: JwksCache
    miniflux_host: str = "127.0.0.1"
    miniflux_port: int = 8081

    # Override logging to route through our logger and skip noisy 200s to
    # /healthcheck so the router probe doesn't flood the log.
    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        path = getattr(self, "path", "")
        if path.startswith("/healthcheck"):
            return
        log.info("%s - " + format, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        self._proxy()

    def do_HEAD(self) -> None:  # noqa: N802
        self._proxy()

    def do_POST(self) -> None:  # noqa: N802
        self._proxy()

    def do_PUT(self) -> None:  # noqa: N802
        self._proxy()

    def do_DELETE(self) -> None:  # noqa: N802
        self._proxy()

    def do_PATCH(self) -> None:  # noqa: N802
        self._proxy()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._proxy()

    def _proxy(self) -> None:
        # Always drop any client-supplied auth header so it cannot be spoofed.
        cleaned_headers = _strip_headers(self.headers.items(), {AUTH_HEADER_NAME})

        # Decide whether this request carries an owner's signed cookie.
        cookies = _parse_cookie_header(self.headers.get("Cookie"))
        token = cookies.get(ZONE_COOKIE, "")
        is_owner = _verify_owner(token, self.jwks)
        if is_owner:
            cleaned_headers.append((AUTH_HEADER_NAME, "admin"))

        # Forward to miniflux on localhost. We cannot rely on http.client to
        # stream a request body that uses Transfer-Encoding: chunked because
        # that header is hop-by-hop and we'd have to re-chunk on the way out,
        # so if Content-Length is absent we read into memory up to a generous
        # cap and re-send with Content-Length. Miniflux requests from the
        # browser use Content-Length already (form submits, JSON POSTs).
        body: bytes | None = None
        content_length_header = self.headers.get("Content-Length")
        if content_length_header:
            try:
                length = int(content_length_header)
            except ValueError:
                self.send_error(400, "invalid Content-Length")
                return
            if length < 0:
                self.send_error(400, "negative Content-Length")
                return
            body = self.rfile.read(length) if length > 0 else b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            # No Content-Length: read whatever's there with a cap. 32 MiB is
            # well above OPML-import and typical Miniflux form POSTs.
            cap = 32 * 1024 * 1024
            body = self.rfile.read(cap)

        try:
            conn = http.client.HTTPConnection(
                self.miniflux_host, self.miniflux_port, timeout=60
            )
            conn.request(
                self.command,
                self.path,
                body=body,
                headers=dict(cleaned_headers),
            )
            upstream = conn.getresponse()
        except (OSError, http.client.HTTPException) as exc:
            log.warning("upstream error: %s", exc)
            self.send_error(502, "Bad Gateway")
            return

        # Stream the response back to the client. Remove hop-by-hop headers
        # and let our own server compute Content-Length / chunking.
        try:
            payload = upstream.read()
        finally:
            upstream.close()
            conn.close()

        self.send_response(upstream.status, upstream.reason)
        for key, value in upstream.getheaders():
            if key.lower() in HOP_BY_HOP_HEADERS:
                continue
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            # Client went away mid-response; nothing to do.
            pass


class DualStackServer(ThreadingHTTPServer):
    # Listen on IPv4; OpenHost's router talks to the container by IPv4 via
    # Docker's bridge. Allow quick restarts.
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    router_url = os.environ.get("OPENHOST_ROUTER_URL", "").strip()
    if not router_url:
        log.error("OPENHOST_ROUTER_URL is not set; refusing to start")
        return 1

    listen_port = int(os.environ.get("AUTH_PROXY_LISTEN_PORT", "8080"))
    miniflux_port = int(os.environ.get("MINIFLUX_UPSTREAM_PORT", "8081"))

    jwks = JwksCache(router_url)
    jwks.prefetch()

    AuthProxyHandler.jwks = jwks
    AuthProxyHandler.miniflux_port = miniflux_port

    server = DualStackServer(("0.0.0.0", listen_port), AuthProxyHandler)
    log.info(
        "listening on 0.0.0.0:%d -> 127.0.0.1:%d (router=%s)",
        listen_port,
        miniflux_port,
        router_url,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
