"""Runtime contract for #56, independent of any provider implementation.

Engineering declaration: dnsid_google_kms.GoogleKmsKeyProvider(client,
key_version_name). Client uses official synchronous get_public_key(request=...)
and asymmetric_sign(request=...) calls. Responses below model public KMS fields.
All dependency interactions are fake-only; cryptography verification is real.
Lifecycle methods intentionally await the separate lifecycle handoff.
"""

from __future__ import annotations

import base64
import importlib
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dnsid import ArgumentError

VERSION = "projects/fixture/locations/global/keyRings/runtime/cryptoKeys/agent/cryptoKeyVersions/7"
# RFC 8032 test 1 seed. Never sourced from SDK code or expected SDK output.
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")


def crc32c(data):
    """Independent reflected Castagnoli CRC, not the provider's helper."""
    value = 0xFFFFFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value ^ 0xFFFFFFFF


class FakeKms:
    """Only existing-version public read and raw-data signing are available."""

    def __init__(self):
        self.private = Ed25519PrivateKey.from_private_bytes(SEED)
        self.calls = []
        self.public_changes = {}
        self.sign_changes = {}

    def get_public_key(self, request):
        self.calls.append(("get_public_key", request))
        assert request["name"] == VERSION
        pem = self.private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        fields = dict(
            name=VERSION, pem=pem, pem_crc32c=crc32c(pem.encode("ascii")),
            algorithm=40, protection_level=1,  # EC_SIGN_ED25519 / SOFTWARE, official enum values
        )
        fields.update(self.public_changes)
        return SimpleNamespace(**fields)

    def asymmetric_sign(self, request):
        self.calls.append(("asymmetric_sign", request))
        assert request["name"] == VERSION
        assert "digest" not in request, "EC_SIGN_ED25519 signs raw DATA, never a digest"
        data = request["data"]
        assert request["data_crc32c"] == crc32c(data)
        signature = self.private.sign(data)
        fields = dict(
            name=VERSION, signature=signature, signature_crc32c=crc32c(signature),
            verified_data_crc32c=True,
        )
        fields.update(self.sign_changes)
        return SimpleNamespace(**fields)


def provider(client):
    # Deliberately no skip/stub: this TC is blocked on the distribution until code lands.
    module = importlib.import_module("dnsid_google_kms")
    return module.GoogleKmsKeyProvider(client, VERSION)


def test_given_independent_crc_fixture_when_checked_then_castagnoli_vector_matches():
    """**Mode**: real-capable (pure fixture self-check)."""
    assert crc32c(b"123456789") == 0xE3069283
    assert crc32c(b"") == 0
    raw = Ed25519PrivateKey.from_private_bytes(SEED).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    assert raw == PUBLIC


@pytest.mark.parametrize("payload", [b"", b"hello DNSid", bytes(range(256))])
def test_given_existing_version_when_signed_then_raw_signature_verifies_independently(payload):
    """**Mode**: fake-only (KMS); Given/When/Then runtime bytes contract."""
    client = FakeKms()
    signer = provider(client)
    signature = signer.sign(payload)
    assert isinstance(signature, bytes)
    assert len(signature) == 64
    client.private.public_key().verify(signature, payload)
    with pytest.raises(InvalidSignature):
        client.private.public_key().verify(signature, payload + b"changed")
    assert [name for name, _ in client.calls].count("asymmetric_sign") == 1


def test_given_same_version_when_reopened_then_public_jwk_and_safe_kid_are_stable():
    """**Mode**: fake-only (KMS); no private key export or mutation API exists."""
    first = provider(FakeKms())
    second = provider(FakeKms())
    key = first.signing_key().to_dict()
    assert key == second.signing_key().to_dict()
    assert key["kty"] == "OKP"
    assert key["crv"] == "Ed25519"
    assert key["alg"] == "EdDSA"
    assert key["x"] == base64.urlsafe_b64encode(PUBLIC).rstrip(b"=").decode("ascii")
    assert key["kid"] and "#" not in key["kid"]
    assert "d" not in key
    assert first.list_key_ids() == [key["kid"]]
    assert first.jwk(key["kid"]).to_dict() == key


@pytest.mark.parametrize("changes", [
    {"name": VERSION[:-1] + "8"},
    {"pem_crc32c": 0},
    {"algorithm": 12},  # RSA_SIGN_PSS_2048_SHA256, not Ed25519
    {"protection_level": 2},  # HSM, not supported software Ed25519
])
def test_given_invalid_public_response_when_opened_then_rejected(changes):
    """**Mode**: fake-only (corrupt/mismatched KMS public response)."""
    client = FakeKms()
    client.public_changes = changes
    with pytest.raises((ArgumentError, ValueError)):
        provider(client).signing_key()
    assert all(name != "asymmetric_sign" for name, _ in client.calls)


@pytest.mark.parametrize("changes", [
    {"name": VERSION[:-1] + "8"},
    {"signature_crc32c": 0},
    {"verified_data_crc32c": False},
])
def test_given_invalid_sign_response_when_signed_then_no_signature_is_returned(changes):
    """**Mode**: fake-only (KMS response integrity and exact version binding)."""
    client = FakeKms()
    client.sign_changes = changes
    signer = provider(client)
    with pytest.raises((ArgumentError, ValueError)):
        signer.sign(b"bound raw DATA")
