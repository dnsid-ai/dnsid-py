"""Real deployment/factory/client/publication/profile chain; fake network only.

Authority: shared SDK design 01, 12 and optional-provider loading, plus Python
JOSE API. No app publication orchestration, persistence, crash or rebinding.
"""

from __future__ import annotations

import base64
import datetime
import json
from types import SimpleNamespace

import google.auth
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from google.auth.credentials import AnonymousCredentials
from google.cloud import kms_v1

from dnsid import (
    ArgumentError,
    DnsIdTxtRecord,
    HTTPSFetcher,
    IdentityManagerDependencies,
    ValidationError,
    VerificationError,
    identity_manager_from_file,
)
from dnsid._crypto import jwk_from_dict
from dnsid._utils import b64url_decode, b64url_encode
from dnsid.c2sp_tlog import (
    C2spTlogVerificationOptions,
    canonical_json,
    create_c2sp_tlog_verification_registry,
    encode_entry_bundle,
    merkle_root_from_entries,
    prepare_event,
)
from dnsid.jose import JoseProfile
from dnsid.models import IssuanceEvent, TLSCertificate, TXTRecord
from tests.conftest import MockDNSResolver
from tests.test_c2sp_migration import _Fetcher, _verifier_key
from tests.test_c2sp_verification_registry import _checkpoint_cosignature, _checkpoint_signature
from tests.test_google_kms_config_contract import publication_document
from tests.test_google_kms_lifecycle_contract import NEXT_SEED, SUCCESSOR, VersionKms
from tests.test_google_kms_runtime_contract import SEED, VERSION

DOMAIN = "agent.example"
LR = "c2sp-tlog:testnet:https://functional.example#existing"


def public_key(private):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw = {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
           "x": b64url_encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))}
    raw["kid"] = jwk_from_dict(raw).thumbprint()
    return jwk_from_dict(raw)


def publication(tmp_path, *, corrupt=None):
    """Independent signed A evidence: expected values never come from provider."""
    private = Ed25519PrivateKey.from_private_bytes(SEED)
    entity = Ed25519PrivateKey.from_private_bytes(bytes([11]) * 32)
    log = Ed25519PrivateKey.from_private_bytes(bytes([12]) * 32)
    witness = Ed25519PrivateKey.from_private_bytes(bytes([13]) * 32)
    key, ek = public_key(private), public_key(entity)
    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    event = IssuanceEvent(domain=DOMAIN, governance_id="example", entity_key=ek,
                          operational_key=key, timestamp=now - datetime.timedelta(minutes=5))
    prepared = prepare_event(event, LR)
    envelope = dict(prepared.envelope)
    envelope["sigs"] = {
        "ae": {"kid": ek.kid, "sig": b64url_encode(entity.sign(prepared.signed_bytes))},
        "op": {"kid": key.kid, "sig": b64url_encode(private.sign(prepared.signed_bytes))},
    }
    entry = canonical_json(envelope).encode()
    # One per-publication clock sample drives event/status/cert/checkpoint.
    # Do not reuse test_c2sp_migration's module-import timestamp: a full suite
    # can take longer than its 60-second checkpoint freshness window.
    root = base64.b64encode(merkle_root_from_entries([entry])).decode()
    signed = f"functional.example\n1\n{root}\n"
    checkpoint = (signed + "\n"
        + _checkpoint_signature("functional.example", signed, log) + "\n"
        + _checkpoint_cosignature("migration-witness", signed, witness, int(now.timestamp()))
        + "\n").encode()
    resources = _Fetcher({
        "https://functional.example/checkpoint": checkpoint,
        "https://functional.example/tile/entries/000.p/1": encode_entry_bundle([entry]),
    })
    policy = ("log " + _verifier_key("functional.example", b"\x01", log)
              + "\nwitness migration-witness " + _verifier_key("migration-witness", b"\x04", witness)
              + "\nquorum migration-witness\n").encode()
    registry = create_c2sp_tlog_verification_registry(C2spTlogVerificationOptions(
        policy_document=policy, resource_fetcher=resources, checkpoint_freshness_ms=600_000,
    ))
    record = DnsIdTxtRecord(
        v="dnsid-draft-01", identity_fqdn=DOMAIN, gi="example", lr=LR,
        ek="https://example/entity.jwks", ku=f"https://{DOMAIN}/jwks",
        su=f"https://{DOMAIN}/status",
    )
    record.sg = b64url_encode(entity.sign(record.canonical().encode("ascii")))
    if corrupt == "record":
        record.sg = b64url_encode(bytes(64))
    if corrupt == "log":
        resources.resources["https://functional.example/tile/entries/000.p/1"] = encode_entry_bundle([entry + b" "])
    cert = TLSCertificate(not_after=now + datetime.timedelta(days=1), san_dns_names=[DOMAIN, "example"])
    responses = {
        record.ek: ({"keys": [ek.to_dict()]}, cert),
        record.ku: ({"keys": [key.to_dict()]}, cert),
        record.su: ({"state": "REVOKED" if corrupt == "status" else "ACTIVE",
                     "lastTransitionAt": now.isoformat()}, cert),
    }
    calls = []

    class Fetcher(HTTPSFetcher):
        def fetch_strict_json(self, url, allowed_host=None, domain_boundary=False, *, revalidate=False):
            calls.append(url)
            assert url in responses, f"unexpected external fetch: {url}"
            return responses[url]

    resolver = MockDNSResolver({f"_dnsid.{DOMAIN}": [TXTRecord([record.serialize().encode()], ttl=60)]})
    if corrupt == "dns":
        resolver = MockDNSResolver()
    deps = IdentityManagerDependencies(dns_resolver=resolver, https_fetcher=Fetcher(), log_registry=registry)
    document = publication_document({"provider": "google-kms", "keyRef": VERSION})
    document["dnsid"]["identity"].update(domain=DOMAIN, governanceId="example", logRef=LR,
        ekUrl=record.ek, kuUrl=record.ku, statusUrl=record.su)
    path = tmp_path / "deployment.json"
    path.write_text(json.dumps(document))
    return SimpleNamespace(path=path, deps=deps, key=key, calls=calls, resources=resources)


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


def checked_profile(manager, payload=b"functional profile payload", *, profile=None):
    profile = profile or JoseProfile.from_identity_manager(manager)
    token = profile.create_jws(payload)
    recovered, verified = profile.verify_jws(token)
    assert recovered == payload and verified.domain == DOMAIN
    header, body, signature = token.split(".")
    kid = manager.key_provider.signing_key().kid
    assert json.loads(b64url_decode(header))["kid"] == f"{DOMAIN}#{kid}"
    assert verified.jwks.key_by_id(kid).verify(f"{header}.{body}".encode(), b64url_decode(signature))
    with pytest.raises(VerificationError):
        profile.verify_jws(f"{header}.{b64url_encode(payload + b'tampered')}.{signature}")
    return token


def test_deployment_official_client_verified_publication_and_profile(tmp_path, official_rpc):
    """**Mode**: fake-only network; config -> real SDK checker -> public JOSE."""
    evidence = publication(tmp_path)
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
    evidence = publication(tmp_path)
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
    evidence = publication(tmp_path, corrupt=corrupt)
    with pytest.raises(VerificationError):
        identity_manager_from_file(evidence.path, deps=evidence.deps)
    assert [name for name, _ in official_rpc.calls] == ["get_public_key"]


def test_pending_generation_preserves_existing_profile_and_allows_pending_proof(tmp_path, official_rpc):
    """**Mode**: fake-only network. No manager rotation workflow is implied."""
    evidence = publication(tmp_path)
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
    evidence = publication(tmp_path)
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
    evidence = publication(tmp_path)
    document = json.loads(evidence.path.read_text())
    document["keySource"]["settings"] = {"algorithm": "EdDSA"}
    evidence.path.write_text(json.dumps(document))
    with identity_manager_from_file(evidence.path, deps=evidence.deps) as manager:
        checked_profile(manager)
    assert official_rpc.calls[0][0] == "get_public_key"
    assert official_rpc.calls[0][1]["name"] == VERSION


def test_unsupported_settings_rejected_before_rpc(tmp_path, official_rpc):
    """**Mode**: fake-only network. Invalid config never opens/generates keys."""
    evidence = publication(tmp_path)
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

    evidence = publication(tmp_path)
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
    evidence = publication(tmp_path)
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
