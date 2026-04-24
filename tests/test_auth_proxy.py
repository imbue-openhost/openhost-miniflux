"""Unit tests for the auth_proxy helper functions.

Setup and invocation are documented in the README's "Development" section.

Scope: the pure helpers that matter for security — JWT verification, cookie
parsing, and header stripping. The HTTP handler's socket I/O is exercised
at deploy time via the smoke-test commands in the README.
"""

from __future__ import annotations

import base64
import os
import sys
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import auth_proxy  # noqa: E402  (sys.path manipulation required)


# ------------------------------------------------------------------- helpers


def _make_keypair() -> tuple[bytes, dict]:
    """Return (pem_bytes, jwk_dict) for a fresh RSA-2048 key."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    numbers = pub.public_numbers()

    def _b64url(i: int, length: int) -> str:
        return (
            base64.urlsafe_b64encode(i.to_bytes(length, "big"))
            .rstrip(b"=")
            .decode()
        )

    n_len = (numbers.n.bit_length() + 7) // 8
    jwk = {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": _b64url(numbers.n, n_len),
        "e": _b64url(numbers.e, 3),
    }
    return pem, jwk


class _StubCache:
    def __init__(self, jwk: dict) -> None:
        self._keys = [jwt.algorithms.RSAAlgorithm.from_jwk(jwk)]

    def get(self):  # noqa: ANN201 - mirrors real JwksCache.get() signature
        return list(self._keys)

    def add_key(self, jwk: dict) -> None:
        self._keys.append(jwt.algorithms.RSAAlgorithm.from_jwk(jwk))


@pytest.fixture
def keypair() -> tuple[bytes, dict]:
    return _make_keypair()


@pytest.fixture
def stub_jwks(keypair) -> _StubCache:
    _, jwk = keypair
    return _StubCache(jwk)


def _token(pem: bytes, sub: str, exp_offset: int = 3600, alg: str = "RS256") -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": sub, "iat": now, "exp": now + exp_offset},
        pem,
        algorithm=alg,
    )


# ----------------------------------------------------------------- _verify_owner


def test_valid_owner_token_passes(keypair, stub_jwks):
    pem, _ = keypair
    assert auth_proxy._verify_owner(_token(pem, "owner"), stub_jwks) is True


def test_expired_owner_token_fails(keypair, stub_jwks):
    pem, _ = keypair
    assert auth_proxy._verify_owner(_token(pem, "owner", exp_offset=-10), stub_jwks) is False


def test_non_owner_subject_fails(keypair, stub_jwks):
    pem, _ = keypair
    assert auth_proxy._verify_owner(_token(pem, "guest"), stub_jwks) is False


def test_missing_token_fails(stub_jwks):
    assert auth_proxy._verify_owner("", stub_jwks) is False


def test_garbage_token_fails(stub_jwks):
    assert auth_proxy._verify_owner("not.a.jwt", stub_jwks) is False


def test_token_signed_by_unknown_key_fails(stub_jwks):
    other_pem, _ = _make_keypair()
    assert auth_proxy._verify_owner(_token(other_pem, "owner"), stub_jwks) is False


def test_token_missing_exp_fails(keypair, stub_jwks):
    pem, _ = keypair
    no_exp = jwt.encode({"sub": "owner"}, pem, algorithm="RS256")
    assert auth_proxy._verify_owner(no_exp, stub_jwks) is False


def test_hs256_token_rejected(stub_jwks):
    """Only RS256 is accepted; algorithm confusion must not let an attacker
    forge a token by treating the public key as an HMAC secret."""
    now = int(time.time())
    hs = jwt.encode(
        {"sub": "owner", "exp": now + 3600},
        "symmetric-secret",
        algorithm="HS256",
    )
    assert auth_proxy._verify_owner(hs, stub_jwks) is False


def test_valid_owner_token_with_multiple_keys(keypair, stub_jwks):
    """During JWKS key rotation we briefly have two keys; the loop must try
    both rather than giving up after a verify-with-non-owner-sub on the wrong
    key."""
    # Add a second (non-signing) key to the cache.
    _, other_jwk = _make_keypair()
    stub_jwks.add_key(other_jwk)
    pem, _ = keypair
    assert auth_proxy._verify_owner(_token(pem, "owner"), stub_jwks) is True


# ------------------------------------------------------------- _parse_cookie_header


def test_parses_simple_cookie():
    c = auth_proxy._parse_cookie_header("foo=bar; zone_auth=abc.def.ghi; baz=qux")
    assert c == {"foo": "bar", "zone_auth": "abc.def.ghi", "baz": "qux"}


def test_empty_and_none_headers():
    assert auth_proxy._parse_cookie_header("") == {}
    assert auth_proxy._parse_cookie_header(None) == {}


def test_first_value_wins_on_duplicate_names():
    """Defense against an attacker appending a garbage duplicate cookie
    after a legitimate one to deny owner access."""
    c = auth_proxy._parse_cookie_header("zone_auth=valid-token; zone_auth=garbage")
    assert c["zone_auth"] == "valid-token"


def test_parts_without_equals_sign_are_skipped():
    """Only parts missing the `=` separator are dropped; parts with an
    empty name (`=value`) are retained under the key `""`. We accept this
    slight liberality because real cookie headers never produce it and we
    don't want to complicate the parser."""
    c = auth_proxy._parse_cookie_header("no-equals-sign; foo=bar; =empty-name")
    assert c == {"foo": "bar", "": "empty-name"}


# ----------------------------------------------------------------- _strip_headers


def test_strip_is_case_insensitive():
    headers = [
        ("Content-Type", "text/html"),
        ("X-Openhost-User", "evil"),
        ("X-openhost-user", "also-evil"),
        ("Cookie", "x=y"),
    ]
    remaining = auth_proxy._strip_headers(headers, {"X-Openhost-User"})
    names = [h[0].lower() for h in remaining]
    assert "x-openhost-user" not in names
    assert "cookie" in names
    assert "content-type" in names


def test_accepts_frozenset_drop_set():
    """The call site passes a frozenset-union; the function must accept it."""
    remaining = auth_proxy._strip_headers(
        [("Host", "x"), ("Content-Type", "y")],
        frozenset({"host"}),
    )
    assert remaining == [("Content-Type", "y")]


# ----------------------------------------------------------------- _port_from_env


def test_port_from_env_accepts_default():
    os.environ.pop("TEST_PORT_VAR", None)
    assert auth_proxy._port_from_env("TEST_PORT_VAR", 12345) == 12345


def test_port_from_env_parses_integer(monkeypatch):
    monkeypatch.setenv("TEST_PORT_VAR", "9001")
    assert auth_proxy._port_from_env("TEST_PORT_VAR", 1) == 9001


def test_port_from_env_rejects_non_integer(monkeypatch):
    monkeypatch.setenv("TEST_PORT_VAR", "definitely-not-a-port")
    with pytest.raises(ValueError):
        auth_proxy._port_from_env("TEST_PORT_VAR", 1)


def test_port_from_env_rejects_out_of_range(monkeypatch):
    monkeypatch.setenv("TEST_PORT_VAR", "70000")
    with pytest.raises(ValueError):
        auth_proxy._port_from_env("TEST_PORT_VAR", 1)


# ----------------------------------------------------------------- JwksCache


def test_jwks_cache_returns_stale_keys_on_refresh_failure(keypair, monkeypatch):
    """If a JWKS refresh fails and we have a previously-cached key, return
    the stale cache rather than failing closed and locking the owner out."""
    _, jwk = keypair
    good_keys = [jwt.algorithms.RSAAlgorithm.from_jwk(jwk)]

    cache = auth_proxy.JwksCache("http://router.invalid")

    # First call: return a valid key.
    fetch_calls = []

    def _fake_fetch() -> list:
        fetch_calls.append(time.time())
        if len(fetch_calls) == 1:
            return good_keys
        raise RuntimeError("router unreachable")

    monkeypatch.setattr(cache, "_fetch", _fake_fetch)

    assert cache.get() is not None
    # Force the TTL to expire so the next get() triggers a refresh attempt.
    cache._fetched_at = 0
    keys = cache.get()
    assert keys == good_keys, "stale cache should be returned on refresh failure"
    assert len(fetch_calls) == 2


def test_jwks_cache_fails_closed_when_no_cache_and_fetch_fails(monkeypatch):
    """With no prior successful fetch, a fetch error must propagate so that
    _verify_owner can fail closed rather than silently letting requests
    through unauthenticated."""
    cache = auth_proxy.JwksCache("http://router.invalid")

    def _fake_fetch() -> list:
        raise RuntimeError("never reachable")

    monkeypatch.setattr(cache, "_fetch", _fake_fetch)
    with pytest.raises(RuntimeError):
        cache.get()


def test_verify_owner_fails_closed_when_jwks_unavailable(keypair, monkeypatch):
    """Integration between _verify_owner and JwksCache: a valid-looking token
    must be rejected when the cache can't return any keys at all."""
    pem, _ = keypair
    cache = auth_proxy.JwksCache("http://router.invalid")

    def _raise() -> list:
        raise RuntimeError("no cache, no fetch")

    monkeypatch.setattr(cache, "get", _raise)
    assert auth_proxy._verify_owner(_token(pem, "owner"), cache) is False


def test_jwks_fetch_skips_malformed_entries(keypair, monkeypatch):
    """A JWKS containing a malformed entry alongside a valid one should
    yield the valid key. This defends against a future key rotation that
    temporarily introduces an unparseable key — we should keep accepting
    the good one rather than locking the owner out entirely."""
    _, good_jwk = keypair
    cache = auth_proxy.JwksCache("http://router.invalid")

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def raise_for_status(self):
            pass

        def json(self):
            return {"keys": [good_jwk, {"kty": "RSA", "broken": True}]}

    monkeypatch.setattr(auth_proxy.requests, "get", lambda *a, **kw: _FakeResp())
    keys = cache._fetch()
    assert len(keys) == 1


def test_jwks_fetch_raises_when_all_entries_malformed(monkeypatch):
    cache = auth_proxy.JwksCache("http://router.invalid")

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def raise_for_status(self):
            pass

        def json(self):
            return {"keys": [{"kty": "RSA", "broken": True}]}

    monkeypatch.setattr(auth_proxy.requests, "get", lambda *a, **kw: _FakeResp())
    with pytest.raises(RuntimeError, match="no usable keys"):
        cache._fetch()


def test_jwks_prefetch_swallows_errors(monkeypatch, caplog):
    """prefetch() is called at startup to warm the cache; a failing router
    must not prevent the server from coming up. Confirm both (a) the
    exception is swallowed and (b) the failure is logged so an operator
    has a breadcrumb."""
    import logging

    cache = auth_proxy.JwksCache("http://router.invalid")

    def _raise() -> list:
        raise RuntimeError("nope")

    monkeypatch.setattr(cache, "_fetch", _raise)
    with caplog.at_level(logging.WARNING, logger="auth_proxy"):
        cache.prefetch()  # must not raise

    # The failure must be visible in the logs. We don't assert the exact
    # message format (that's an implementation detail) — just that _some_
    # warning mentioning the failure was emitted.
    assert any("prefetch" in rec.message.lower() for rec in caplog.records), (
        "prefetch() failure must be logged"
    )
