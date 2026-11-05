"""Code-blind runtime guards and actual optional-package composition for #56.

Authority: compliance@939d241 core KeyProvider, configuration loading and
key-provider-packages contracts. No lifecycle orchestration is exercised.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from dnsid import ArgumentError
from dnsid.config_loading import construct_identity_manager
from tests.test_google_kms_config_contract import load_document
from tests.test_google_kms_runtime_contract import (
    PUBLIC,
    VERSION,
    FakeKms,
    crc32c,
    provider,
)


class ServiceUnavailable(Exception):
    """Independent service failure, not a provider exception type."""


@pytest.mark.parametrize("operation", ["get_public_key", "asymmetric_sign"])
def test_given_service_failure_when_opening_or_signing_then_no_result_or_substitute(operation):
    """**Mode**: fake-only (KMS service exceptions). Given/When/Then: fail closed."""
    client = FakeKms()
    attempted = []

    def unavailable(request):
        attempted.append(request["name"])
        raise ServiceUnavailable("fixture KMS unavailable")

    setattr(client, operation, unavailable)
    with pytest.raises((ServiceUnavailable, ArgumentError, ValueError)):
        provider(client).sign(b"must not return a substitute signature")
    assert attempted == [VERSION]
    assert all(request["name"] == VERSION for _, request in client.calls)


@pytest.mark.parametrize("kind", ["malformed", "p256"])
def test_given_valid_crc_but_invalid_spki_when_opened_then_no_signer_is_returned(kind):
    """**Mode**: fake-only (KMS); valid transport integrity is not key validity."""
    client = FakeKms()
    if kind == "malformed":
        pem = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
    else:
        pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
    client.public_changes = {"pem": pem, "pem_crc32c": crc32c(pem.encode("ascii"))}
    with pytest.raises((ArgumentError, ValueError, TypeError)):
        provider(client).sign(b"must not sign with an invalid Ed25519 key")
    assert all(name != "asymmetric_sign" for name, _ in client.calls)


@pytest.mark.parametrize("length", [0, 63, 65])
def test_given_wrong_signature_length_with_valid_crc_when_signed_then_rejected(length):
    """**Mode**: fake-only (KMS). Given/When/Then: integrity alone is insufficient."""
    client = FakeKms()
    signature = b"x" * length
    client.sign_changes = {"signature": signature, "signature_crc32c": crc32c(signature)}
    with pytest.raises((ArgumentError, ValueError)):
        provider(client).sign(b"invalid raw signature length")
    assert [name for name, _ in client.calls].count("asymmetric_sign") == 1


def test_given_selected_installed_google_when_constructed_then_manager_uses_exact_existing_key(
    tmp_path, monkeypatch, local_publication,
):
    """**Mode**: fake-only (KMS client and downstream publication evidence).

    Given the actual installed optional package and documented deployment file,
    when public composition constructs the manager, then public key publication
    and independently verified signatures use the configured immutable version.
    Neither factories nor provider module are replaced.
    """
    import google.cloud.kms_v1 as kms

    client = FakeKms()
    monkeypatch.setattr(kms, "KeyManagementServiceClient", lambda: client)
    loaded = load_document(tmp_path, {"provider": "google-kms", "keyRef": VERSION})
    before = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    manager = None
    construction_error = None
    try:
        manager = construct_identity_manager(loaded)
    except Exception as error:
        construction_error = error
    assert construction_error is None, (
        "actual installed Google factory must compose a KeyProvider into the manager; "
        f"received {type(construction_error).__name__}: {construction_error}"
    )
    assert manager is not None
    key = manager.key_provider.signing_key().to_dict()
    assert key["x"] == base64.urlsafe_b64encode(PUBLIC).rstrip(b"=").decode("ascii")
    assert key["alg"] == "EdDSA" and key["crv"] == "Ed25519"
    assert key["kid"] and "#" not in key["kid"] and "d" not in key
    assert manager.key_provider.list_key_ids() == [key["kid"]]
    for payload in (b"", bytes(range(256))):
        signature = manager.key_provider.sign(payload)
        client.private.public_key().verify(signature, payload)
    assert loaded.key_source.key_ref == VERSION
    assert all(name in {"get_public_key", "asymmetric_sign"} for name, _ in client.calls)
    assert all(request["name"] == VERSION for _, request in client.calls)
    after = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert after == before
