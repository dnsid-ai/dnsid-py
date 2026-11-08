"""Real deployment/factory/client/publication/profile chain; fake network only.

Authority: shared SDK design 01, 12 and optional-provider loading, plus Python
JOSE API. No app publication orchestration, persistence, crash or rebinding.
"""

from __future__ import annotations

import json

import google.auth
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from google.auth.credentials import AnonymousCredentials
from google.cloud import kms_v1

from dnsid import (
    ArgumentError,
    ValidationError,
    VerificationError,
    identity_manager_from_file,
)
from dnsid._utils import b64url_decode
from dnsid.jose import JoseProfile
from tests._kms_publication import DOMAIN, checked_profile, public_key, publication
from tests.test_google_kms_lifecycle_contract import NEXT_SEED, SUCCESSOR, VersionKms
from tests.test_google_kms_runtime_contract import VERSION


@pytest.fixture
def official_rpc(monkeypatch):
    """Keep actual factory, client constructor and protobuf conversion real.

    Only ADC credentials and generated transport RPC callables are replaced.
    """
    from google.cloud.kms_v1.services.key_management_service.transports.grpc import (
        KeyManagementServiceGrpcTransport,
    )

    service = VersionKms()
    original = KeyManagementServiceGrpcTransport.__init__
    transports = []
    monkeypatch.setattr(google.auth, "default", lambda **kw: (AnonymousCredentials(), "fixture"))

    def initialize(transport, *args, **kwargs):
        original(transport, *args, **kwargs)
        transports.append(transport)
        for operation, request_type, response_type in (
            ("get_public_key", kms_v1.GetPublicKeyRequest, kms_v1.PublicKey),
            ("asymmetric_sign", kms_v1.AsymmetricSignRequest, kms_v1.AsymmetricSignResponse),
            ("create_crypto_key_version", kms_v1.CreateCryptoKeyVersionRequest, kms_v1.CryptoKeyVersion),
        ):
            def rpc(request, *, operation=operation, request_type=request_type,
                    response_type=response_type, **kw):
                assert isinstance(request, request_type)
                fields = request_type.to_dict(request)
                if operation == "asymmetric_sign":
                    assert not request._pb.HasField("digest"), "Ed25519 must not send a digest"
                    fields["data"] = request.data
                    fields["data_crc32c"] = request.data_crc32c
                    # Protobuf JSON includes an absent message as a default;
                    # remove it only AFTER asserting wire-level absence above.
                    fields.pop("digest", None)
                response = getattr(service, operation)(fields)
                return response_type(**vars(response))
            transport._wrapped_methods[getattr(transport, operation)] = rpc

    monkeypatch.setattr(KeyManagementServiceGrpcTransport, "__init__", initialize)
    yield service
    for transport in transports:
        transport.close()


def test_deployment_official_client_verified_publication_and_profile(tmp_path, official_rpc):
    """**Mode**: fake-only network; config -> real SDK checker -> public JOSE."""
    evidence = publication(tmp_path, key_source={"provider": "google-kms", "keyRef": VERSION})
    before = evidence.path.read_bytes()
    with identity_manager_from_file(evidence.path, deps=evidence.deps) as manager:
        assert manager.key_provider.signing_key().to_dict() == evidence.key.to_dict()
        observed = manager.verify_local_publication()
        assert observed.domain == DOMAIN and observed.jwks.keys == [evidence.key]
        checked_profile(manager)
        assert evidence.calls and evidence.resources.calls
        assert all(name in {"get_public_key", "asymmetric_sign"} for name, _ in official_rpc.calls)
        assert {request["name"] for _, request in official_rpc.calls} == {VERSION}
    assert evidence.path.read_bytes() == before


def test_selected_key_b_cannot_bind_valid_publication_a(tmp_path, official_rpc):
    """**Mode**: fake-only network. No implicit rotation, generation or fallback."""
    evidence = publication(tmp_path, key_source={"provider": "google-kms", "keyRef": VERSION})
    official_rpc.keys[SUCCESSOR] = Ed25519PrivateKey.from_private_bytes(NEXT_SEED)
    document = json.loads(evidence.path.read_text())
    document["keySource"]["keyRef"] = SUCCESSOR
    evidence.path.write_text(json.dumps(document))
    before = evidence.path.read_bytes()
    with pytest.raises(ValidationError, match="configured signer does not match local publication"):
        identity_manager_from_file(evidence.path, deps=evidence.deps)
    assert evidence.calls and evidence.resources.calls
    assert [name for name, _ in official_rpc.calls] == ["get_public_key"]
    assert official_rpc.calls[0][1]["name"] == SUCCESSOR
    assert evidence.path.read_bytes() == before


@pytest.mark.parametrize("corrupt", ["record", "status", "log", "dns"])
def test_invalid_evidence_rejected_before_profile_signing(tmp_path, official_rpc, corrupt):
    """**Mode**: fake-only network. Real SDK checker rejects bad evidence."""
    evidence = publication(tmp_path, key_source={"provider": "google-kms", "keyRef": VERSION}, corrupt=corrupt)
    with pytest.raises(VerificationError):
        identity_manager_from_file(evidence.path, deps=evidence.deps)
    assert [name for name, _ in official_rpc.calls] == ["get_public_key"]


def test_pending_generation_preserves_existing_profile_and_allows_pending_proof(tmp_path, official_rpc):
    """**Mode**: fake-only network. No manager rotation workflow is implied."""
    evidence = publication(tmp_path, key_source={"provider": "google-kms", "keyRef": VERSION})
    with identity_manager_from_file(evidence.path, deps=evidence.deps) as manager:
        old = manager.key_provider.signing_key().kid
        profile = JoseProfile.from_identity_manager(manager)
        pending = manager.key_provider.generate_key()
        assert pending != old and manager.key_provider.list_key_ids() == [old]
        assert manager.get_key_set().keys == [evidence.key]
        proof = b"pending ownership proof"
        assert manager.key_provider.jwk(pending).verify(proof, manager.key_provider.sign_key(pending, proof))
        token = checked_profile(manager, profile=profile)
        assert profile.verify_jws(token)[0] == b"functional profile payload"
        manager.key_provider.activate(pending)
        # Same-provider static consumer, not dynamic cross-provider rebinding.
        next_token = profile.create_jws(b"explicit activation")
        header, body, signature = next_token.split(".")
        assert json.loads(b64url_decode(header))["kid"] == f"{DOMAIN}#{pending}"
        assert manager.key_provider.jwk(pending).verify(f"{header}.{body}".encode(), b64url_decode(signature))
        # Activation alone does not update the still-A public publication.
        with pytest.raises(VerificationError):
            profile.verify_jws(next_token)
        assert manager.get_key_set().keys == [manager.key_provider.jwk(pending)]


@pytest.mark.parametrize("failure", ["create", "read", "metadata"])
def test_generation_failure_preserves_consumer_and_leaves_no_pending(tmp_path, official_rpc, failure):
    """**Mode**: fake-only KMS failures. Failed version never becomes eligible."""
    evidence = publication(tmp_path, key_source={"provider": "google-kms", "keyRef": VERSION})
    with identity_manager_from_file(evidence.path, deps=evidence.deps) as manager:
        old = manager.key_provider.signing_key().kid
        profile = JoseProfile.from_identity_manager(manager)
        checked_profile(manager, profile=profile)
        original = official_rpc.get_public_key
        successor_reads = []
        if failure == "create":
            def fail(request):
                official_rpc.calls.append(("create_crypto_key_version", request))
                raise ArgumentError("fixture create failure")
            official_rpc.create_crypto_key_version = fail
        else:
            def fail(request):
                if request["name"] == SUCCESSOR:
                    successor_reads.append(request["name"])
                    if failure == "read":
                        official_rpc.calls.append(("get_public_key", request))
                        raise ArgumentError("fixture public read failure")
                    response = original(request)
                    response.algorithm = 12
                    return response
                return original(request)
            official_rpc.get_public_key = fail
        expected_error = {
            "create": "fixture create failure",
            "read": "fixture public read failure",
            "metadata": "google-kms requires EC_SIGN_ED25519",
        }[failure]
        with pytest.raises(ArgumentError, match=expected_error):
            manager.key_provider.generate_key()
        assert successor_reads == ([] if failure == "create" else [SUCCESSOR])
        assert manager.key_provider.signing_key().kid == old
        assert manager.key_provider.list_key_ids() == [old]
        assert manager.get_key_set().keys == [evidence.key]
        checked_profile(manager, profile=profile)
        phantom = public_key(Ed25519PrivateKey.from_private_bytes(NEXT_SEED)).kid
        before = len(official_rpc.calls)
        with pytest.raises(ArgumentError, match="unknown key ID"):
            manager.key_provider.jwk(phantom)
        with pytest.raises(ArgumentError):
            manager.key_provider.sign_key(phantom, b"not a registered pending proof")
        with pytest.raises(ArgumentError):
            manager.key_provider.activate(phantom)
        assert len(official_rpc.calls) == before
        assert sum(name == "create_crypto_key_version" for name, _ in official_rpc.calls) == 1


def test_explicit_eddsa_settings_use_installed_factory(tmp_path, official_rpc):
    """**Mode**: fake-only network. Deployment settings use JOSE EdDSA."""
    evidence = publication(tmp_path, key_source={"provider": "google-kms", "keyRef": VERSION})
    document = json.loads(evidence.path.read_text())
    document["keySource"]["settings"] = {"algorithm": "EdDSA"}
    evidence.path.write_text(json.dumps(document))
    with identity_manager_from_file(evidence.path, deps=evidence.deps) as manager:
        checked_profile(manager)
    assert official_rpc.calls[0][0] == "get_public_key"
    assert official_rpc.calls[0][1]["name"] == VERSION


def test_unsupported_settings_rejected_before_rpc(tmp_path, official_rpc):
    """**Mode**: fake-only network. Invalid config never opens/generates keys."""
    evidence = publication(tmp_path, key_source={"provider": "google-kms", "keyRef": VERSION})
    document = json.loads(evidence.path.read_text())
    document["keySource"]["settings"] = {"algorithm": "ES256"}
    evidence.path.write_text(json.dumps(document))
    with pytest.raises(ArgumentError, match="only algorithm EdDSA"):
        identity_manager_from_file(evidence.path, deps=evidence.deps)
    assert official_rpc.calls == []
    assert evidence.calls == [] and evidence.resources.calls == []


@pytest.mark.parametrize("operation", ["get_public_key", "asymmetric_sign"])
def test_external_open_or_sign_failure_propagates_without_substitution(tmp_path, official_rpc, operation):
    """**Mode**: fake-only KMS. Exact external failure reaches public caller."""
    from google.api_core.exceptions import PermissionDenied

    evidence = publication(tmp_path, key_source={"provider": "google-kms", "keyRef": VERSION})
    failure = PermissionDenied("fixture denies selected version")
    attempted = []

    def denied(request):
        attempted.append(request["name"])
        raise failure

    if operation == "get_public_key":
        official_rpc.get_public_key = denied
        with pytest.raises(PermissionDenied) as caught:
            identity_manager_from_file(evidence.path, deps=evidence.deps)
        assert evidence.calls == [] and evidence.resources.calls == []
    else:
        with identity_manager_from_file(evidence.path, deps=evidence.deps) as manager:
            profile = JoseProfile.from_identity_manager(manager)
            checked_profile(manager, profile=profile)
            official_rpc.asymmetric_sign = denied
            with pytest.raises(PermissionDenied) as caught:
                profile.create_jws(b"must not return substitute signature")
            assert manager.key_provider.signing_key().to_dict() == evidence.key.to_dict()
    assert caught.value is failure
    assert attempted == [VERSION]
    assert all(name != "create_crypto_key_version" for name, _ in official_rpc.calls)


def test_retained_supersession_preserves_activated_successor_consumer(tmp_path, official_rpc):
    """**Mode**: fake-only network. Retiring old A does not clear active B."""
    evidence = publication(tmp_path, key_source={"provider": "google-kms", "keyRef": VERSION})
    with identity_manager_from_file(evidence.path, deps=evidence.deps) as manager:
        profile = JoseProfile.from_identity_manager(manager)
        old = manager.key_provider.signing_key().kid
        pending = manager.key_provider.generate_key()
        manager.key_provider.activate(pending)
        before = len(official_rpc.calls)
        manager.key_provider.supersede(old)
        assert len(official_rpc.calls) == before
        assert manager.key_provider.list_key_ids() == [pending]
        token = profile.create_jws(b"successor remains usable")
        header, body, signature = token.split(".")
        assert json.loads(b64url_decode(header))["kid"] == f"{DOMAIN}#{pending}"
        assert manager.key_provider.jwk(pending).verify(
            f"{header}.{body}".encode(), b64url_decode(signature))
        before = len(official_rpc.calls)
        with pytest.raises(ArgumentError):
            manager.key_provider.sign_key(old, b"no retired signing")
        assert len(official_rpc.calls) == before
