"""Provisional GCP lifecycle proof against compliance@3e5d4d7ca662270739aa28b9e0d86fac2a704949.

Authority (proposed, not accepted): 01 KeyProvider Interface and 12 Google Cloud
KMS Ed25519. Scope is provider-local eligibility, not manager orchestration or
recovery. Engineering seam: GoogleKmsKeyProvider(client, key_version_name),
with official-shaped create_crypto_key_version(request=...) on the same client.
"""

from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dnsid import ArgumentError
from tests.test_google_kms_runtime_contract import SEED, VERSION, crc32c, provider

PARENT = VERSION.rsplit("/cryptoKeyVersions/", 1)[0]
SUCCESSOR = PARENT + "/cryptoKeyVersions/8"
# RFC 8032 vector 2, independent of provider code and distinct from the active fixture.
NEXT_SEED = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
NEXT_PUBLIC = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")


class VersionKms:
    """Fake-only KMS: creation never changes which version an explicit name signs.

    No create-CryptoKey, disable, destroy, import or export operation is provided.
    If a provider attempts one, the test fails rather than silently accepting it.
    """

    def __init__(self):
        self.keys = {VERSION: Ed25519PrivateKey.from_private_bytes(SEED)}
        self.calls = []

    def create_crypto_key_version(self, request):
        self.calls.append(("create_crypto_key_version", request))
        assert request["parent"] == PARENT
        assert SUCCESSOR not in self.keys, "fixture permits exactly one explicit generation"
        self.keys[SUCCESSOR] = Ed25519PrivateKey.from_private_bytes(NEXT_SEED)
        return SimpleNamespace(name=SUCCESSOR, algorithm=40, state=1, protection_level=1)

    def get_public_key(self, request):
        self.calls.append(("get_public_key", request))
        name = request["name"]
        pem = self.keys[name].public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        return SimpleNamespace(
            name=name, pem=pem, pem_crc32c=crc32c(pem.encode("ascii")),
            algorithm=40, protection_level=1,
        )

    def asymmetric_sign(self, request):
        self.calls.append(("asymmetric_sign", request))
        assert "digest" not in request
        assert request["data_crc32c"] == crc32c(request["data"])
        signature = self.keys[request["name"]].sign(request["data"])
        return SimpleNamespace(
            name=request["name"], signature=signature,
            signature_crc32c=crc32c(signature), verified_data_crc32c=True,
        )


def successful_lifecycle_operation(signer, name, *args):
    """Assert the public operator call succeeds before checking its state effects."""
    error = None
    result = None
    try:
        result = getattr(signer, name)(*args)
    except Exception as caught:
        error = caught
    assert error is None, (
        f"KeyProvider.{name} must complete the explicit lifecycle operation; "
        f"received {type(error).__name__}: {error}"
    )
    return result


def generated_signer():
    client = VersionKms()
    signer = provider(client)
    previous = signer.signing_key().to_dict()
    pending = successful_lifecycle_operation(signer, "generate_key")
    assert isinstance(pending, str) and pending and "#" not in pending
    assert pending != previous["kid"]
    return client, signer, previous, pending


def assert_signing_rejected_without_kms(client, operation):
    before = len(client.calls)
    with pytest.raises((ArgumentError, ValueError)):
        operation()
    assert len(client.calls) == before, "locally ineligible keys must not reach KMS"


def test_given_existing_version_when_opened_then_no_version_is_generated():
    """**Mode**: fake-only (KMS). Given/When/Then: opening is read-only."""
    client = VersionKms()
    signer = provider(client)
    signer.signing_key()
    signer.sign(b"existing version")
    assert set(client.keys) == {VERSION}
    assert all(name != "create_crypto_key_version" for name, _ in client.calls)


def test_given_active_version_when_generated_then_pending_does_not_replace_active():
    """**Mode**: fake-only (KMS). Given/When/Then: explicit generation stays pending."""
    client, signer, previous, pending = generated_signer()
    assert signer.signing_key().to_dict() == previous
    assert signer.list_key_ids() == [previous["kid"]]
    assert pending not in signer.list_key_ids()
    assert [request["parent"] for name, request in client.calls
            if name == "create_crypto_key_version"] == [PARENT]
    client.keys[VERSION].public_key().verify(signer.sign(b"still active"), b"still active")
    # Reopening the same configured version cannot silently follow the generated one.
    reopened = provider(client)
    assert reopened.signing_key().to_dict() == previous
    assert reopened.list_key_ids() == [previous["kid"]]


@pytest.mark.parametrize("payload", [b"", b"rotation proof", bytes(range(256))])
def test_given_pending_key_when_explicitly_signed_then_independent_proof_verifies(payload):
    """**Mode**: fake-only (KMS). Given/When/Then: pending JWK/SignKey are available."""
    client, signer, previous, pending = generated_signer()
    public = signer.jwk(pending).to_dict()
    assert public["kid"] == pending
    assert public["kty"] == "OKP" and public["crv"] == "Ed25519"
    assert public["alg"] == "EdDSA" and "d" not in public
    assert public["x"] == base64.urlsafe_b64encode(NEXT_PUBLIC).rstrip(b"=").decode("ascii")
    signature = signer.sign_key(pending, payload)
    assert isinstance(signature, bytes) and len(signature) == 64
    client.keys[SUCCESSOR].public_key().verify(signature, payload)
    assert signer.signing_key().to_dict() == previous
    assert signer.list_key_ids() == [previous["kid"]]


def test_given_pending_key_when_activated_then_previous_signing_is_locally_superseded():
    """**Mode**: fake-only (KMS). Given/When/Then: only explicit activation promotes."""
    client, signer, previous, pending = generated_signer()
    successful_lifecycle_operation(signer, "activate", pending)
    assert signer.list_key_ids() == [pending]
    assert signer.signing_key().to_dict() == signer.jwk(pending).to_dict()
    client.keys[SUCCESSOR].public_key().verify(signer.sign(b"new active"), b"new active")
    assert_signing_rejected_without_kms(
        client, lambda: signer.sign_key(previous["kid"], b"retired authorization"),
    )
    # Retiring a retained previous version must not clear its active successor.
    successful_lifecycle_operation(signer, "supersede", previous["kid"])
    assert signer.list_key_ids() == [pending]
    client.keys[SUCCESSOR].public_key().verify(signer.sign(b"successor"), b"successor")
    assert set(client.keys) == {VERSION, SUCCESSOR}


def test_given_explicit_active_retirement_permission_then_no_signing_or_cloud_mutation():
    """**Mode**: fake-only (KMS). Given/When/Then: local retirement is not cloud deletion."""
    client = VersionKms()
    signer = provider(client)
    kid = signer.signing_key().kid
    before = len(client.calls)
    signer.supersede(kid, allow_active=True)
    assert len(client.calls) == before, "supersession must not mutate cloud versions"
    assert signer.list_key_ids() == []
    assert_signing_rejected_without_kms(client, lambda: signer.sign(b"retired"))
    assert_signing_rejected_without_kms(client, lambda: signer.sign_key(kid, b"retired"))
    assert_signing_rejected_without_kms(client, signer.signing_key)
    assert set(client.keys) == {VERSION}


@pytest.mark.parametrize("permission", [None, False])
def test_active_retirement_requires_existing_interface_permission(permission):
    """**Mode**: fake-only KMS. KeyProvider.supersede guard, as local/AWS.

    The former unconditional-active test contradicted interfaces.KeyProvider:
    active retirement is reserved for publicly verified cross-provider rotation.
    Explicit permission is tested separately; no cloud retirement is implied.
    """
    client = VersionKms()
    signer = provider(client)
    previous = signer.signing_key().to_dict()
    before = len(client.calls)
    kwargs = {} if permission is None else {"allow_active": permission}
    with pytest.raises(ArgumentError):
        signer.supersede(previous["kid"], **kwargs)
    assert len(client.calls) == before
    assert signer.signing_key().to_dict() == previous
    assert signer.list_key_ids() == [previous["kid"]]
    payload = b"guard rejection preserves active signing"
    client.keys[VERSION].public_key().verify(signer.sign(payload), payload)
