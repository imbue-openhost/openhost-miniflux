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
for authenticated owners. Non-owner visitors to a public path (Miniflux's
`/healthcheck` is listed in `openhost.toml`'s `public_paths`) could forge the
header. We mirror the mirotalk pattern — verify a signed JWT ourselves — so the
app stays safe regardless of which paths are public.

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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

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
        # `_cache_lock` guards reads/writes of _keys and _fetched_at. It is
        # only ever held briefly — never across the blocking HTTP fetch.
        self._cache_lock = threading.Lock()
        # `_fetch_lock` serialises the HTTP fetch itself so only one thread
        # at a time calls the router while others keep serving cached keys.
        self._fetch_lock = threading.Lock()

    def _fetch(self) -> list:
        url = f"{self._router_url}{JWKS_PATH}"
        # Use a context manager so the underlying connection is released on
        # every exit path (success, HTTPError from raise_for_status, JSON
        # decode error, etc.).
        with requests.get(url, timeout=5) as resp:
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
        # Fast path: return cached keys without touching either lock beyond
        # the brief snapshot read.
        with self._cache_lock:
            cached_keys = self._keys
            cached_at = self._fetched_at
        if cached_keys and (time.time() - cached_at) < JWKS_REFRESH_INTERVAL_SEC:
            return cached_keys

        # Serialise refreshes across threads so we only fetch once even under
        # concurrent bursts. Other threads block only on this lock, not on
        # the network I/O directly.
        with self._fetch_lock:
            # Another thread may have refreshed while we waited.
            with self._cache_lock:
                cached_keys = self._keys
                cached_at = self._fetched_at
            if cached_keys and (time.time() - cached_at) < JWKS_REFRESH_INTERVAL_SEC:
                return cached_keys

            try:
                keys = self._fetch()
            except Exception as exc:  # noqa: BLE001 - log+fallback
                if cached_keys:
                    log.warning(
                        "JWKS refresh failed, using cached keys: %s", exc
                    )
                    return cached_keys
                log.warning("JWKS fetch failed and no cache: %s", exc)
                raise

            with self._cache_lock:
                self._keys = keys
                self._fetched_at = time.time()
            log.info("refreshed JWKS (%d key(s))", len(keys))
            return keys

    def prefetch(self) -> None:
        try:
            self.get()
        except Exception as exc:  # noqa: BLE001
            log.warning("initial JWKS prefetch failed (will retry on demand): %s", exc)


def _parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    """Parse an RFC6265 Cookie header into a {name: value} dict.

    Uses first-value-wins semantics for duplicate cookie names. Browsers
    send most-specific-path / most-specific-domain cookies first, so the
    first occurrence is what the site "meant" to set. This also prevents a
    trivial denial-of-service where a hostile client appends a duplicate
    `zone_auth=garbage` after the real cookie to make us reject an
    otherwise valid owner token.

    Purposefully lenient on encoding: JWT values only contain URL-safe
    base64 characters + two dots so decoding is a no-op in practice.
    """
    if not cookie_header:
        return {}
    result: dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        result.setdefault(name.strip(), value.strip())
    return result


def _verify_owner(token: str, jwks: JwksCache) -> bool:
    """Return True if the JWT is a valid router-signed owner token."""
    if not token:
        return False
    try:
        keys = jwks.get()
    except Exception as exc:  # noqa: BLE001
        # No keys available and nothing cached. Fail closed, but surface the
        # reason so an operator investigating "I can't log in" has a trail.
        log.warning("JWKS unavailable; denying owner check: %s", exc)
        return False

    # Try each key; RS256 verification, require exp claim, no audience check
    # (the router doesn't set aud). If any key verifies and the subject is
    # "owner", accept. We continue the loop on both invalid-signature errors
    # and successful-but-non-owner decodes so a JWKS rollover (old key still
    # present while the new one takes over) can't accidentally stop
    # accepting legitimate owner tokens.
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
    return False


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


class AuthProxyHandler(BaseHTTPRequestHandler):
    # `jwks` is set by main() before the server is started. The ClassVar
    # default of None guards against construction order bugs (e.g. a test
    # that instantiates the handler without running main()): a clear
    # RuntimeError is friendlier than an AttributeError at request time.
    jwks: JwksCache | None = None
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

    # Cap on request-body memory so a crafted or buggy client cannot drive the
    # proxy OOM by sending `Content-Length: 2147483647`. 32 MiB comfortably
    # covers Miniflux form submits (including OPML uploads on the order of a
    # few MiB). Requests larger than this get a 413.
    MAX_BODY_BYTES = 32 * 1024 * 1024

    # Read timeout on the client socket. A slow-loris client dripping body
    # bytes over minutes would otherwise tie up a server thread indefinitely,
    # leading to thread exhaustion under concurrency.
    CLIENT_READ_TIMEOUT_SECONDS = 60

    def _proxy(self) -> None:
        # Apply a read timeout to the incoming socket so a slow client can't
        # hold a thread forever while sending the request body.
        try:
            self.connection.settimeout(self.CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            # Very unlikely (socket already closed); nothing to recover.
            pass


        # Strip (a) the auth header (never trust client-supplied), (b)
        # hop-by-hop headers (Connection, Transfer-Encoding, etc.), and (c)
        # Content-Length — we rebuild the body into a buffered request below
        # and set a fresh Content-Length from the actual bytes we send.
        # Forwarding the client's Content-Length or Transfer-Encoding would
        # confuse the upstream when the two disagree.
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | {AUTH_HEADER_NAME.lower(), "content-length"},
        )

        # Decide whether this request carries an owner's signed cookie. The
        # jwks class attribute should always be set by main() before the
        # server accepts requests; if not, fail closed rather than letting
        # a None deref crash the handler.
        if self.jwks is None:
            log.error("auth-proxy JWKS not initialised; refusing request")
            self.send_error(503, "auth-proxy not initialised")
            return
        cookies = _parse_cookie_header(self.headers.get("Cookie"))
        token = cookies.get(ZONE_COOKIE, "")
        is_owner = _verify_owner(token, self.jwks)
        if is_owner:
            cleaned_headers.append((AUTH_HEADER_NAME, "admin"))

        # Reject chunked (and any other non-identity) transfer encoding
        # outright. We buffer the body into a new Content-Length request;
        # forwarding the raw chunked bytes as a plain body would corrupt
        # the upstream's parse, and implementing dechunking here duplicates
        # what the fronting OpenHost router (httpx-based) already does
        # before it reaches us. 501 is the correct status code: the
        # semantic issue is "we do not implement this transfer-coding", not
        # "please add Content-Length and try again" (which 411 would imply
        # and which would send a client into a retry loop).
        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower().strip()
        if transfer_encoding and transfer_encoding != "identity":
            self.send_error(501, "Transfer-Encoding not supported")
            return

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
            if length > self.MAX_BODY_BYTES:
                # Reject before allocating. Without this cap a hostile client
                # could advertise a multi-GiB body and exhaust container RAM.
                self.send_error(413, "request body too large")
                return
            if length > 0:
                try:
                    body = self.rfile.read(length)
                except (OSError, TimeoutError) as exc:
                    # Client dropped the connection or the socket timeout
                    # we set at the top of _proxy() fired. Return 400 so
                    # the client sees a clean response instead of a raw
                    # traceback in the server log.
                    log.info("client read error: %s", exc)
                    try:
                        self.send_error(400, "request body read failed")
                    except OSError:
                        # Client is already gone; nothing left to say.
                        pass
                    return
            else:
                body = b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            # Body method with no Content-Length and no Transfer-Encoding.
            # The HTTP spec says this means "no body" for a request (unlike a
            # response, which can use connection-close framing). Forward an
            # empty body rather than blocking waiting for EOF, which would
            # otherwise let a slow client tie up a handler thread until the
            # 60s socket timeout fires.
            body = b""

        # The outer try/finally guarantees the upstream socket is always
        # released, even if conn.request() or getresponse() raises. We use
        # putrequest/putheader rather than conn.request() so that duplicate
        # header names (e.g. multiple Set-Cookie on the request direction or
        # chained X-Forwarded-For entries) are each preserved — conn.request()
        # takes a dict and would silently collapse duplicates to the last
        # value.
        conn = http.client.HTTPConnection(
            self.miniflux_host, self.miniflux_port, timeout=60
        )
        try:
            try:
                # Let http.client set its own Host header to `127.0.0.1:8081`;
                # Miniflux generates absolute URLs from its $BASE_URL env var
                # (set by start.sh from $OPENHOST_ZONE_DOMAIN) and doesn't
                # rely on Host for that. `skip_accept_encoding` avoids
                # http.client adding `Accept-Encoding: identity` if the
                # client omitted the header.
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_accept_encoding=True,
                )
                for key, value in cleaned_headers:
                    conn.putheader(key, value)
                if body is not None:
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self.send_error(502, "Bad Gateway")
                return

            # Read the upstream body into memory. We have to buffer anyway
            # because we rewrite Content-Length, and streaming would mean
            # handling Transfer-Encoding: chunked end-to-end. A read failure
            # here gets the same treatment as a failure during the request
            # phase: log and return 502 if we haven't written headers yet.
            try:
                try:
                    payload = upstream.read()
                finally:
                    upstream.close()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream read error: %s", exc)
                self.send_error(502, "Bad Gateway")
                return

            # Forward upstream's status + headers. We leave upstream's
            # Content-Length intact because for HEAD it's the only way the
            # client learns the size a real GET would return; for everything
            # else it matches len(payload) anyway since we just read the
            # whole body.
            self.send_response(upstream.status, upstream.reason)
            for key, value in upstream.getheaders():
                if key.lower() in HOP_BY_HOP_HEADERS:
                    continue
                self.send_header(key, value)
            self.end_headers()

            # HEAD responses MUST NOT include a message body (RFC 9110 §9.3.2).
            # http.client already returns an empty payload for HEAD but
            # suppress the write unconditionally for clarity.
            if self.command == "HEAD":
                return
            try:
                self.wfile.write(payload)
            except OSError as exc:
                # BrokenPipeError, ConnectionResetError, TimeoutError, and
                # ECONNABORTED are all signals that the client went away
                # mid-response. Nothing we can do except log at debug and
                # avoid crashing the handler thread.
                log.debug("client disconnected mid-response: %s", exc)
        finally:
            conn.close()


class IPv4ThreadingServer(ThreadingHTTPServer):
    # OpenHost's router talks to the container over Docker's bridge network
    # on IPv4, so we explicitly bind IPv4 and don't advertise dual-stack
    # capability. allow_reuse_address lets us come back up quickly after a
    # crash, daemon_threads ensures request threads don't keep the process
    # alive on shutdown.
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    """Read a port from an env var, with a clear error on non-integer input."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    router_url = os.environ.get("OPENHOST_ROUTER_URL", "").strip()
    if not router_url:
        log.error("OPENHOST_ROUTER_URL is not set; refusing to start")
        return 1

    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 8080)
        miniflux_port = _port_from_env("MINIFLUX_UPSTREAM_PORT", 8081)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    jwks = JwksCache(router_url)
    jwks.prefetch()

    AuthProxyHandler.jwks = jwks
    AuthProxyHandler.miniflux_port = miniflux_port

    try:
        server = IPv4ThreadingServer(("0.0.0.0", listen_port), AuthProxyHandler)
    except OSError as exc:
        # Typically "address already in use" if something else is already
        # bound. Fail with a clear message instead of a raw traceback so
        # the operator can see what's wrong in the container logs.
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port,
            exc,
        )
        return 1
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
