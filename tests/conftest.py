"""Shared test fixtures — real cryptographic key pairs and a signing KeyProvider."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from dnsid import JWK
from dnsid._crypto import (
    ec_public_jwk_dict,
    ec_sign,
    ed25519_public_jwk_dict,
    ed25519_sign,
    jwk_from_dict,
)
from dnsid.enums import DNSSECState
from dnsid.interfaces import DNSResolver, KeyProvider
from dnsid.models import TXTRecord
from tests._config import make_config

# ---------------------------------------------------------------------------
# Key pair generation helpers
# ---------------------------------------------------------------------------


def make_ec_p256_pair(kid: str = "k1") -> tuple[ec.EllipticCurvePrivateKey, JWK]:
    private = ec.generate_private_key(ec.SECP256R1())
    raw = ec_public_jwk_dict(private, kid, "ES256")
    return private, jwk_from_dict(raw)


def make_ed25519_pair(kid: str = "k1") -> tuple[ed25519.Ed25519PrivateKey, JWK]:
    private = ed25519.Ed25519PrivateKey.generate()
    raw = ed25519_public_jwk_dict(private, kid)
    return private, jwk_from_dict(raw)


# ---------------------------------------------------------------------------
# Real-crypto KeyProvider
# ---------------------------------------------------------------------------


class RealKeyProvider(KeyProvider):
    """KeyProvider backed by actual cryptography private keys.

    Supports EC P-256 and Ed25519 keys.
    """

    def __init__(
        self,
        active_kid: str,
        keys: dict[str, tuple[ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey, JWK]],
    ) -> None:
        self._active_kid = active_kid
        self._keys = keys  # kid -> (private_key, JWK)

    def signing_key(self) -> JWK:
        return self._keys[self._active_kid][1]

    def jwk(self, kid: str) -> JWK:
        return self._keys[kid][1]

    def list_key_ids(self) -> list[str]:
        rest = [k for k in self._keys if k != self._active_kid]
        return [self._active_kid] + rest

    def sign(self, payload: bytes) -> bytes:
        private, pub = self._keys[self._active_kid]
        alg = pub.alg
        if alg == "EdDSA":
            return ed25519_sign(private, payload)  # type: ignore[arg-type]
        return ec_sign(private, alg, payload)  # type: ignore[arg-type]

    def generate_key(self) -> str:
        raise NotImplementedError

    def activate(self, kid: str) -> None:
        raise NotImplementedError

    def supersede(self, kid: str) -> None:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ec_pair():
    """Returns (private_key, JWK) for an ES256 key."""
    return make_ec_p256_pair("k1")


@pytest.fixture()
def ed_pair():
    """Returns (private_key, JWK) for an EdDSA key."""
    return make_ed25519_pair("k1")


@pytest.fixture()
def ec_provider(ec_pair):
    private, pub = ec_pair
    return RealKeyProvider("k1", {"k1": (private, pub)})


@pytest.fixture()
def ed_provider(ed_pair):
    private, pub = ed_pair
    return RealKeyProvider("k1", {"k1": (private, pub)})


@pytest.fixture()
def base_config():
    return make_config(
        domain="agent.example.com",
        governance_id="example.com",
        log_ref="microledger:abc123",
        status_url="https://agent.example.com/status",
    )


class MockDNSResolver(DNSResolver):
    """DNS resolver that serves pre-configured TXT records."""

    def __init__(self, records: dict[str, list[TXTRecord]] | None = None) -> None:
        self._records = records or {}

    def fetch_txt(self, name: str) -> tuple[list[TXTRecord], DNSSECState]:
        return self._records.get(name, []), DNSSECState.UNSIGNED
