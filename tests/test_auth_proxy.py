"""Unit tests for the auth_proxy helper functions.

Run: `pip install 'PyJWT[crypto]==2.9.0' requests pytest`, then
`pytest tests/ -q` from the repo root.

These tests do not exercise the HTTP handler's socket I/O (that's covered by
the end-to-end tests documented in the README). They cover the pure helpers
that matter for security: JWT verification and cookie parsing.
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
def jwks_with(keypair) -> _StubCache:
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


def test_valid_owner_token_passes(keypair, jwks_with):
    pem, _ = keypair
    assert auth_proxy._verify_owner(_token(pem, "owner"), jwks_with) is True


def test_expired_owner_token_fails(keypair, jwks_with):
    pem, _ = keypair
    assert auth_proxy._verify_owner(_token(pem, "owner", exp_offset=-10), jwks_with) is False


def test_non_owner_subject_fails(keypair, jwks_with):
    pem, _ = keypair
    assert auth_proxy._verify_owner(_token(pem, "guest"), jwks_with) is False


def test_missing_token_fails(jwks_with):
    assert auth_proxy._verify_owner("", jwks_with) is False


def test_garbage_token_fails(jwks_with):
    assert auth_proxy._verify_owner("not.a.jwt", jwks_with) is False


def test_token_signed_by_unknown_key_fails(jwks_with):
    other_pem, _ = _make_keypair()
    assert auth_proxy._verify_owner(_token(other_pem, "owner"), jwks_with) is False


def test_token_missing_exp_fails(keypair, jwks_with):
    pem, _ = keypair
    no_exp = jwt.encode({"sub": "owner"}, pem, algorithm="RS256")
    assert auth_proxy._verify_owner(no_exp, jwks_with) is False


def test_hs256_token_rejected(jwks_with):
    """Only RS256 is accepted; algorithm confusion must not let an attacker
    forge a token by treating the public key as an HMAC secret."""
    now = int(time.time())
    hs = jwt.encode(
        {"sub": "owner", "exp": now + 3600},
        "symmetric-secret",
        algorithm="HS256",
    )
    assert auth_proxy._verify_owner(hs, jwks_with) is False


def test_valid_owner_token_with_multiple_keys(keypair, jwks_with):
    """During JWKS key rotation we briefly have two keys; the loop must try
    both rather than giving up after a verify-with-non-owner-sub on the wrong
    key."""
    # Add a second (non-signing) key to the cache.
    _, other_jwk = _make_keypair()
    jwks_with.add_key(other_jwk)
    pem, _ = keypair
    assert auth_proxy._verify_owner(_token(pem, "owner"), jwks_with) is True


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


def test_malformed_parts_are_skipped():
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
