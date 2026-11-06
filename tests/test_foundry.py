"""Known Foundry's durable boundaries with fake registry, DNS, HTTPS, and log."""

from __future__ import annotations

import copy
import datetime
import hashlib
import json
import multiprocessing
import os
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import dnsid
from dnsid import (
    FoundryConfig,
    IdentityManagerDependencies,
    LoadedConfig,
    LocalKeyProvider,
    LogRef,
    PreparedRegistryEvent,
    SubmissionResult,
)
from dnsid._utils import b64url_decode_strict, b64url_encode
from dnsid._verification_budget import verification_budget
from dnsid.c2sp_tlog import (
    C2spSignerRole,
    C2spTlogReader,
    C2spVerificationContext,
    entry_bytes,
    prepare_event,
    sign_prepared_event,
)
from dnsid.c2sp_tlog.canonical import canonical_bytes
from dnsid.enums import DNSSECState
from dnsid.exceptions import NoActiveSigningKeyError, RegistryRequestError
from dnsid.foundry import (
    FileFoundryStore,
    FoundryBusy,
    FoundryDeadline,
    FoundryError,
    FoundryStateError,
    KeyMismatch,
    KeyMissing,
    KeyRevoked,
    SigningPaused,
    TerminalIdentity,
    UnsupportedAlgorithm,
    UnsupportedContract,
    UnsupportedRegistry,
    WorkflowOutcome,
    create,
)
from dnsid.foundry.store import issuance_key, recovery_document, registration_key, validate_name
from dnsid.models import (
    AgentRegistration,
    DnsIdTxtRecord,
    IssuanceEvent,
    LiveProofResponse,
    PublicationConfig,
    TLSCertificate,
    TXTRecord,
)
from dnsid.registry_client import _live_provisioning_from_response

ORG = "11111111-1111-4111-8111-111111111111"
DOMAIN = "agent.example.com"
LR = "c2sp-tlog:testnet:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"
GI = "example.com"


class PublicDNS:
    def __init__(self, server):
        self.server = server
        self.missing = False
        self.calls = 0

    def fetch_txt(self, name):
        self.calls += 1
        assert name == f"_dnsid.{DOMAIN}"
        if self.missing:
            return [], DNSSECState.UNKNOWN
        record = DnsIdTxtRecord(
            v="dnsid-draft-01",
            gi=self.server.public_gi,
            ek=f"https://{GI}/keys",
            ku=f"https://{DOMAIN}/keys",
            lr=self.server.public_lr,
            su=f"https://{DOMAIN}/status",
            identity_fqdn=DOMAIN,
        )
        record.sg = b64url_encode(self.server.entity.sign(record.canonical().encode("ascii")))
        return [TXTRecord([record.serialize().encode("ascii")], ttl=60)], DNSSECState.UNKNOWN


class PublicHTTPS:
    def __init__(self, server):
        self.server = server
        self.urls = []

    def fetch_strict_json(self, url, allowed_host=None, domain_boundary=False, *, revalidate=False):
        self.urls.append(url)
        certificate = TLSCertificate(
            not_after=datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1),
            san_dns_names=[GI, DOMAIN],
        )
        if url.endswith("/status"):
            return {
                "state": self.server.public_status,
                "lastTransitionAt": "2026-11-01T00:00:00Z",
                **(
                    {"revocationReason": "KEY_COMPROMISE"}
                    if self.server.public_status == "REVOKED"
                    else {}
                ),
            }, certificate
        assert allowed_host in {GI, DOMAIN}
        key = self.server.entity if allowed_host == GI else self.server.public_provider
        return {"keys": [key.signing_key().to_dict()]}, certificate


class FoundryServer:
    _base_url = "https://registry.example"

    def __init__(self, provider):
        self.provider = provider
        self.public_provider = provider
        self.entity = LocalKeyProvider.generate()
        self.status = "READY"
        self.public_status = "ACTIVE"
        self.public_gi = GI
        self.public_lr = LR
        self.proof_required = False
        self.omit_domain = False
        self.proof_expired = False
        self.onboarding_error = None
        self.onboarding = {
            "org_id": ORG,
            "governance_domain": GI,
            "gi": {"domain": GI, "state": "verified", "gate_authorized": True},
            "ek": {"status": "verified"},
        }
        self.history = []
        self.prepared = None
        self.created = []
        self.submitted = []
        self.proofs = []
        self.reissues = []
        self.prepare_calls = 0
        self.submit_error = None
        self.lose_create = False
        self.competitor = False
        self.lose_proof = False
        self.reader = Mock(spec=C2spTlogReader)
        self.reader._load_complete_history.side_effect = self.load_history
        self.reader.verify_non_revocation.return_value = SimpleNamespace(logged_state="ACTIVE")
        self.reader.verify_bilateral_binding.return_value = SimpleNamespace(
            initial_operational_thumbprint=provider.signing_key().thumbprint(),
        )
        self.logs = Mock(new_reader=Mock(return_value=self.reader))
        self.dns = PublicDNS(self)
        self.https = PublicHTTPS(self)
        self.publication = PublicationConfig(
            "dnsid-draft-01",
            GI,
            f"https://{DOMAIN}/keys",
            f"https://{GI}/keys",
            LR,
            f"https://{DOMAIN}/status",
        )

    def load_history(self, *args, **kwargs):
        from dnsid.c2sp_tlog.errors import C2spTlogVerificationError

        if not self.history:
            raise C2spTlogVerificationError("lifecycle contains no ISSUANCE event")
        return SimpleNamespace(current_stream_events=list(self.history))

    def get_organization_onboarding(self):
        if self.onboarding_error:
            raise self.onboarding_error
        return copy.deepcopy(self.onboarding)

    def challenge(self, key, request_id):
        expiry = datetime.datetime.now(datetime.UTC) + datetime.timedelta(
            seconds=-60 if self.proof_expired else 3600,
        )
        transcript = {
            "protocol": "dnsid-live-provisioning-pop/v1",
            "org_id": ORG,
            "agent_id": "id-1",
            "fqdn": DOMAIN,
            "key_id": key.thumbprint(),
            "nonce": "proof-nonce",
            "expires_at": expiry.isoformat(),
        }
        return {
            "request_id": request_id,
            "agent_id": "id-1",
            "status": "challenge_pending",
            "challenge": "proof-nonce",
            "challenge_message": b64url_encode(canonical_bytes(transcript)),
        }

    def register_live_agent(self, request, idempotency_key):
        self.created.append((request, idempotency_key))
        if request.public_key_jwk.thumbprint() != self.provider.signing_key().thumbprint():
            raise RegistryRequestError("/agent", 409, "KEY_MISMATCH")
        if self.lose_create:
            self.lose_create = False
            raise TimeoutError("lost create response")
        if self.proof_required:
            raw = self.challenge(request.public_key_jwk, idempotency_key)
        else:
            raw = {
                "request_id": idempotency_key,
                "agent_id": "id-1",
                "status": self.status,
                "challenge": "",
                "challenge_message": "",
            }
            if not self.omit_domain:
                raw["domain"] = DOMAIN
        return _live_provisioning_from_response(raw, request.public_key_jwk)

    def get_registration(self, domain):
        assert domain == DOMAIN
        return AgentRegistration(
            DOMAIN,
            "registry",
            self.status,
            self._base_url,
            publication_config=self.publication,
            id="id-1",
        )

    def submit_live_proof(self, domain, request):
        self.proofs.append(request)
        self.status = "READY"
        if self.lose_proof:
            raise TimeoutError("lost proof response")
        return LiveProofResponse(request.request_id, "id-1", "PROVISIONING")

    def reissue_live_proof(self, domain, request):
        self.reissues.append(request)
        self.proof_expired = False
        response = _live_provisioning_from_response(
            self.challenge(request.public_key_jwk, request.request_id),
            request.public_key_jwk,
        )
        return response

    def prepare_issuance(self, domain, idempotency_key):
        self.prepare_calls += 1
        if self.history:
            raise RegistryRequestError("/prepare", 409, "TLOG_PREPARATION_MISMATCH")
        if self.prepared is None:
            event = IssuanceEvent(
                domain=DOMAIN,
                governance_id=GI,
                entity_key=self.entity.signing_key(),
                operational_key=self.provider.signing_key(),
                timestamp=datetime.datetime(2026, 11, 1, tzinfo=datetime.UTC),
            )
            prepared = sign_prepared_event(
                prepare_event(event, LR), C2spSignerRole.ENTITY, self.entity
            )
            self.prepared = PreparedRegistryEvent(canonical_bytes(prepared.envelope))
        return self.prepared

    def submit_prepared_event(self, domain, data, idempotency_key):
        self.submitted.append((domain, data, idempotency_key))
        if self.submit_error:
            raise self.submit_error
        from dnsid.c2sp_tlog import parse_prepared_issuance
        from dnsid.c2sp_tlog.event_codec import parse_c2sp_event_entry

        if self.competitor:
            raw = json.loads(data)
            raw["ts"] += 1
            raw.pop("sigs")
            context = C2spVerificationContext(
                fqdn=DOMAIN,
                gi=GI,
                entity_key=self.entity.signing_key(),
                operational_key=self.provider.signing_key(),
            )
            prepared = parse_prepared_issuance(canonical_bytes(raw), context)
            prepared = sign_prepared_event(prepared, C2spSignerRole.ENTITY, self.entity, context)
            prepared = sign_prepared_event(
                prepared,
                C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE,
                self.provider,
                context,
            )
            data = entry_bytes(prepared, context)
        parsed = parse_c2sp_event_entry(data)
        if not self.history:
            self.history.append(SimpleNamespace(index=0, data=data, event=parsed))
        if self.competitor:
            return SubmissionResult("rejected", error_code="IDEMPOTENCY_MISMATCH")
        return SubmissionResult(
            "accepted", hashlib.sha256(data).hexdigest(), 0, LogRef.parse(f"{LR}@0")
        )


@pytest.fixture
def setup(tmp_path):
    provider = LocalKeyProvider.generate()
    server = FoundryServer(provider)
    store = FileFoundryStore(tmp_path / "state")
    config = LoadedConfig(foundry=FoundryConfig(ORG, "Example.COM."))
    deps = IdentityManagerDependencies(
        log_registry=server.logs,
        dns_resolver=server.dns,
        https_fetcher=server.https,
    )
    arguments = dict(
        config=config, key_provider=provider, registry_client=server, store=store, deps=deps
    )
    return server, store, arguments


def saved(store, name="billing-agent"):
    key = (FoundryServer._base_url, ORG, name)
    with store.lock(key):
        return store.load(key)


def test_hash_vectors_and_exact_names():
    initial = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    registration = registration_key(ORG, "billing-agent", initial)
    assert registration == "2sWNUpI4tnAzJ3quPrT78uJNVdo96m4En3cZsggktcA"
    assert issuance_key(registration) == "pxQMSC0k-V9nn9qLqMRDczyUxyNyQE87LbGuK5SEWGw"
    assert validate_name("\u00a0cafe\u0301\u3000") == "\u00a0cafe\u0301\u3000"
    assert validate_name("😀" * 255) == "😀" * 255
    names = ["agent", "Agent", "agent ", "café", "cafe\u0301", "\u00a0cafe\u0301\u3000"]
    assert len({registration_key(ORG, name, initial) for name in names}) == len(names)
    assert registration_key(ORG, "café", initial) == "kBdivhIHZhZ_20_Ku_KnIVYE7x0iSw4K1ceQb2s6fxs"


@pytest.mark.parametrize("name", ["", "\ud800", "😀" * 256, 5])
def test_invalid_name_before_discovery(setup, name):
    server, _, arguments = setup
    server.get_organization_onboarding = Mock(side_effect=AssertionError("discovery"))
    with pytest.raises(dnsid.exceptions.ArgumentError):
        create(name, **arguments)
    assert not server.created


def test_create_then_public_active_and_profile_signing(setup):
    server, store, arguments = setup
    with create("billing-agent", **arguments) as identity:
        assert identity.domain == DOMAIN and identity.state is None
        with pytest.raises(SigningPaused):
            identity.sign(b"message")
        with pytest.raises(SigningPaused):
            identity.identity_manager()
        assert identity.active() is identity
        assert identity.state == "ACTIVE"
        assert arguments["key_provider"].signing_key().verify(b"message", identity.sign(b"message"))
        manager = identity.identity_manager()
        assert manager is identity.identity_manager()
        assert manager.key_provider is identity._signer
        assert manager.key_provider.signing_key().verify(
            b"other", manager.key_provider.sign(b"other")
        )
        assert saved(store)["phase"] == "complete"
        assert server.prepare_calls == len(server.submitted) == 1
        identity.active()
        assert len(server.submitted) == 1 and server.dns.calls >= 2


def test_readiness_does_not_change_application_counterparty_policy(setup):
    _, _, arguments = setup
    arguments["config"].dnsid.verification.trusted_entities = []
    with create("billing-agent", **arguments) as identity:
        identity.active()
        manager = identity.identity_manager()
        assert manager.config.verification.trusted_entities == ()
        assert arguments["config"].dnsid.verification.trusted_entities == []


def test_reopen_completed_without_public_network_or_reissuance(setup):
    server, store, arguments = setup
    with create("billing-agent", **arguments) as identity:
        identity.active()
    server.dns.fetch_txt = Mock(side_effect=AssertionError("public DNS"))
    server.https.fetch_strict_json = Mock(side_effect=AssertionError("public HTTPS"))
    with create("billing-agent", **arguments) as identity:
        identity.sign(b"restart")
        assert identity.state is None
    assert len(server.created) == len(server.submitted) == 1


def test_replay_without_domain_keeps_facts_and_resumes(setup):
    server, store, arguments = setup
    server.omit_domain = True
    with pytest.raises(FoundryError) as caught:
        create("billing-agent", **arguments)
    assert caught.value.resumable and caught.value.identity_id == "id-1"
    assert not caught.value.domain
    assert saved(store)["identityId"] == "id-1"
    server.omit_domain = False
    with create("billing-agent", **arguments) as identity:
        assert identity.domain == DOMAIN
    assert server.created[0][1] == server.created[1][1]


def test_lost_create_uses_frozen_request(setup):
    server, store, arguments = setup
    server.lose_create = True
    with pytest.raises(FoundryError):
        create("billing-agent", **arguments)
    assert saved(store)["phase"] == "creation-pending"
    with create("billing-agent", **arguments):
        pass
    assert server.created[0] == server.created[1]


@pytest.mark.parametrize("code", [404, 405])
def test_unsupported_onboarding_never_mutates(setup, code):
    server, _, arguments = setup
    server.onboarding_error = RegistryRequestError("/onboarding", code)
    with pytest.raises(UnsupportedRegistry):
        create("billing-agent", **arguments)
    assert not server.created


@pytest.mark.parametrize(
    "change,expected",
    [
        ({"org_id": "other"}, UnsupportedContract),
        ({"gi": {}}, UnsupportedRegistry),
        ({"ek": {"status": "pending"}}, WorkflowOutcome),
        ({"governance_domain": "other.example"}, UnsupportedContract),
    ],
)
def test_account_bindings_before_mutation(setup, change, expected):
    server, _, arguments = setup
    server.onboarding.update(change)
    with pytest.raises(expected):
        create("billing-agent", **arguments)
    assert not server.created


def test_empty_provider_only_calls_ensure_if_supported(setup):
    server, store, arguments = setup
    provider = arguments["key_provider"]
    empty = Mock(spec=LocalKeyProvider)
    empty.signing_key.side_effect = NoActiveSigningKeyError()
    arguments["key_provider"] = empty
    with pytest.raises(KeyMissing):
        create("billing-agent", **arguments)
    empty.generate_key.assert_not_called()
    empty.ensure_signing_key = Mock(
        side_effect=lambda: setattr(empty.signing_key, "side_effect", None)
    )
    empty.signing_key.return_value = provider.signing_key()
    with create("billing-agent", **arguments):
        pass
    empty.ensure_signing_key.assert_called_once()
    empty.signing_key.side_effect = NoActiveSigningKeyError()
    with pytest.raises(KeyMissing):
        create("billing-agent", **arguments)
    assert empty.ensure_signing_key.call_count == 1


def test_wrong_key_saved_and_stateless_replica(setup):
    server, store, arguments = setup
    with create("billing-agent", **arguments):
        pass
    arguments["key_provider"] = LocalKeyProvider.generate()
    with pytest.raises(KeyMismatch) as caught:
        create("billing-agent", **arguments)
    assert caught.value.identity_id == "id-1" and len(server.created) == 1
    arguments["store"] = FileFoundryStore(store.directory.parent / "replica")
    with pytest.raises(KeyMismatch) as caught:
        create("billing-agent", **arguments)
    assert caught.value.error_code == "KEY_MISMATCH"


@pytest.mark.parametrize(
    "state,error",
    [
        ("ERROR", WorkflowOutcome),
        ("REJECTED", WorkflowOutcome),
        ("CANCELLED", WorkflowOutcome),
        ("RETIRED", TerminalIdentity),
        ("REVOKED", TerminalIdentity),
    ],
)
def test_registry_outcomes_never_replace(setup, state, error):
    server, store, arguments = setup
    identity = create("billing-agent", **arguments)
    server.status = state
    with pytest.raises(error):
        identity.active()
    with pytest.raises(error):
        create("billing-agent", **arguments)
    assert len(server.created) == 1 and not server.submitted
    identity.close()


def test_unknown_registry_state_waits_to_deadline(setup):
    server, store, arguments = setup
    with create("billing-agent", **arguments) as identity:
        server.status = "FUTURE_STATE"
        with pytest.raises(FoundryDeadline):
            identity.active(timeout=0.02)
        assert identity.registry_status == "FUTURE_STATE" and identity.state is None
        assert not server.submitted


@pytest.mark.parametrize("condition", ["status", "dns"])
def test_registry_ready_is_not_public_active(setup, condition):
    server, store, arguments = setup
    if condition == "status":
        server.public_status = "PENDING"
    else:
        server.dns.missing = True
    with create("billing-agent", **arguments) as identity:
        with pytest.raises(FoundryDeadline):
            identity.active(timeout=1.0)
        assert saved(store)["phase"] == "issuance-accepted"
        with pytest.raises(SigningPaused):
            identity.sign(b"message")
        manager = identity.identity_manager()
        with pytest.raises(SigningPaused):
            manager.key_provider.sign(b"profile")
        server.public_status = "ACTIVE"
        server.dns.missing = False
        identity.active()
        assert manager is identity.identity_manager()
        assert len(server.submitted) == 1


@pytest.mark.parametrize("binding", ["key", "gi", "log"])
def test_wrong_public_binding_fails_closed(setup, binding):
    server, store, arguments = setup
    if binding == "key":
        server.public_provider = LocalKeyProvider.generate()
    elif binding == "gi":
        server.public_gi = "other.example"
    else:
        server.public_lr += "different"
    with create("billing-agent", **arguments) as identity:
        with pytest.raises(FoundryError):
            identity.active()
        with pytest.raises(SigningPaused):
            identity.sign(b"message")


def test_no_history_read_before_initial_preparation_or_on_indeterminate_submission(setup):
    server, _, arguments = setup
    server.reader._load_complete_history.side_effect = AssertionError("premature history scan")
    server.submit_error = TimeoutError("outcome unknown")
    with create("billing-agent", **arguments) as identity:
        with pytest.raises(FoundryDeadline):
            identity.active(timeout=1.0)
        assert server.submitted
        server.reader._load_complete_history.assert_not_called()
        server.submit_error = None
        identity.active()
        server.reader._load_complete_history.assert_not_called()


@pytest.mark.parametrize("stage", ["preparation", "submission"])
@pytest.mark.parametrize("empty_result", [False, True])
def test_rejection_before_log_visibility_resumes_on_next_active(setup, stage, empty_result):
    server, store, arguments = setup
    with create("billing-agent", **arguments) as identity:
        if stage == "preparation":
            original_prepare = server.prepare_issuance

            def reject_prepare(domain, key):
                prepared = original_prepare(domain, key)
                from dnsid.c2sp_tlog import parse_prepared_issuance
                from dnsid.c2sp_tlog.event_codec import parse_c2sp_event_entry

                context = C2spVerificationContext(
                    fqdn=DOMAIN,
                    gi=GI,
                    entity_key=server.entity.signing_key(),
                    operational_key=server.provider.signing_key(),
                )
                completed = sign_prepared_event(
                    parse_prepared_issuance(prepared.entry_bytes, context),
                    C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE,
                    server.provider,
                    context,
                )
                data = entry_bytes(completed, context)
                server.history.append(
                    SimpleNamespace(index=0, data=data, event=parse_c2sp_event_entry(data))
                )
                raise RegistryRequestError("/prepare", 409, "TLOG_PREPARATION_MISMATCH")

            server.prepare_issuance = reject_prepare
        else:
            server.competitor = True
        original_load = server.load_history
        if empty_result:
            server.reader._load_complete_history.side_effect = lambda *a, **kw: SimpleNamespace(
                current_stream_events=[],
            )
        else:
            from dnsid.c2sp_tlog.errors import C2spTlogVerificationError

            server.reader._load_complete_history.side_effect = C2spTlogVerificationError(
                "lifecycle contains no ISSUANCE event",
            )
        with pytest.raises(FoundryError) as caught:
            identity.active()
        assert caught.value.resumable and caught.value.identity_id == "id-1"
        assert saved(store)["phase"] != "complete"
        with pytest.raises(SigningPaused):
            identity.sign(b"pending")
        prepares, submissions = server.prepare_calls, len(server.submitted)
        server.reader._load_complete_history.side_effect = original_load
        assert identity.active() is identity
        assert server.prepare_calls == prepares and len(server.submitted) == submissions
        assert saved(store)["phase"] == "complete"
        assert (
            b64url_decode_strict(saved(store)["issuance"]["entryBytes"]) == server.history[0].data
        )


@pytest.mark.parametrize("kind", ["invalid", "unavailable"])
def test_rejection_never_ignores_invalid_or_unavailable_log_evidence(setup, kind):
    from dnsid.c2sp_tlog.errors import C2spTlogTransportError, C2spTlogVerificationError

    server, _, arguments = setup
    server.competitor = True
    error = (
        C2spTlogVerificationError("invalid signature")
        if kind == "invalid"
        else (C2spTlogTransportError("unavailable log", transient=True))
    )
    server.reader._load_complete_history.side_effect = error
    with create("billing-agent", **arguments) as identity:
        for _ in range(2):
            with pytest.raises(FoundryError) as caught:
                identity.active()
            assert caught.value.__cause__ is error
            with pytest.raises(SigningPaused):
                identity.sign(b"pending")
        assert len(server.submitted) == server.prepare_calls == 1


def test_competing_valid_issuance_is_recovered_not_resubmitted(setup):
    server, store, arguments = setup
    server.competitor = True
    with create("billing-agent", **arguments) as identity:
        identity.active()
        document = saved(store)
        accepted = b64url_decode_strict(document["issuance"]["entryBytes"])
        assert accepted != server.submitted[0][1]
        assert accepted == server.history[0].data
        identity.active()
        assert len(server.submitted) == 1


def test_stateless_same_key_replica_adopts_accepted_history(setup):
    server, store, arguments = setup
    with create("billing-agent", **arguments) as identity:
        identity.active()
    arguments["store"] = FileFoundryStore(store.directory.parent / "replica")
    with create("billing-agent", **arguments) as identity:
        identity.active()
    assert server.prepare_calls == 2 and len(server.submitted) == 1
    assert len(server.created) == 2 and server.created[0] == server.created[1]


def test_interrupted_issuance_retries_identical_bytes_after_restart(setup):
    server, store, arguments = setup
    server.submit_error = TimeoutError("lost submission")
    with create("billing-agent", **arguments) as identity:
        with pytest.raises(FoundryDeadline):
            identity.active(timeout=1.0)
    original = server.submitted[0]
    server.submit_error = None
    with create("billing-agent", **arguments) as identity:
        identity.active()
    assert server.submitted[-1] == original and server.prepare_calls == 1


def test_expired_unused_proof_reissued_and_exact_bytes_signed(setup):
    server, store, arguments = setup
    server.proof_required = server.proof_expired = True
    server.status = "VERIFICATION"
    with create("billing-agent", **arguments) as identity:
        initial = saved(store)
        assert not server.proofs
        identity.active()
        proof = saved(store)["proof"]
        request = server.proofs[0]
        assert request.public_key_jwk.verify(
            b64url_decode_strict(proof["challengeMessage"]),
            b64url_decode_strict(request.signature),
        )
        assert proof["challengeMessage"] != initial["proof"]["challengeMessage"]
        assert request.request_id == initial["requestId"]
        assert len(server.created) == len(server.reissues) == 1


def test_proof_lost_response_resumes_from_registry_state(setup):
    server, store, arguments = setup
    server.proof_required = server.lose_proof = True
    server.status = "VERIFICATION"
    with create("billing-agent", **arguments) as identity:
        with pytest.raises(FoundryError):
            identity.active()
    with create("billing-agent", **arguments) as identity:
        identity.active()
    assert len(server.proofs) == len(server.created) == 1 and not server.reissues


def test_refresh_terminal_public_observation_pauses_existing_profiles(setup):
    server, store, arguments = setup
    with create("billing-agent", **arguments) as identity:
        identity.active()
        manager = identity.identity_manager()
        server.public_status = "RETIRED"
        with pytest.raises(TerminalIdentity):
            identity.active()
        assert identity.state == "RETIRED"
        with pytest.raises(SigningPaused):
            manager.key_provider.sign(b"profile")


def test_algorithms_and_revoked_credentials(setup):
    server, _, arguments = setup
    original = arguments["key_provider"]
    arguments["key_provider"] = LocalKeyProvider.generate("ES256")
    with pytest.raises(UnsupportedAlgorithm):
        create("billing-agent", **arguments)
    arguments["key_provider"] = original
    for code, expected in [("KEY_REVOKED", KeyRevoked), ("FORBIDDEN", FoundryError)]:
        server.onboarding_error = RegistryRequestError("/onboarding", 403, code)
        with pytest.raises(expected) as caught:
            create("billing-agent", **arguments)
        assert caught.value.error_code == code
        if code == "FORBIDDEN":
            assert not isinstance(caught.value, KeyRevoked)
    assert not server.created


def test_cancellation_and_provider_deadline(setup):
    server, _, arguments = setup
    provider = arguments["key_provider"]
    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(FoundryDeadline):
        create("billing-agent", **arguments, cancelled=cancelled)
    signing_key = provider.signing_key
    deadlines = []

    def with_deadline(*, deadline=None):
        if deadline is not None:
            deadlines.append(deadline)
        return signing_key()

    provider.signing_key = with_deadline
    with create("billing-agent", **arguments):
        pass
    assert deadlines


def test_portable_roundtrip_unknown_members_private_files_and_id_lookup(setup):
    server, store, arguments = setup
    with create("billing-agent", **arguments) as identity:
        identity.active()
    key = (server._base_url, ORG, "billing-agent")
    with store.lock(key):
        document = store.load(key)
        document["futureMember"] = {"future": "value"}
        document["publicationConfig"]["futureMember"] = "preserved"
        document["issuance"]["futureMember"] = "preserved"
        store.save(key, document)
        exported = store.export_operation(key)
    assert exported == canonical_bytes(json.loads(exported))
    destination = FileFoundryStore(store.directory.parent / "imported")
    destination.import_operation(exported)
    assert destination.load_by_id("id-1") == document
    if os.name != "nt":
        assert store.directory.stat().st_mode & 0o077 == 0
        assert all(path.stat().st_mode & 0o077 == 0 for path in store.directory.iterdir())
    arguments["store"] = destination
    with create("billing-agent", **arguments) as identity:
        identity.active()
    rewritten = saved(destination)
    assert rewritten["futureMember"] == {"future": "value"}
    assert rewritten["publicationConfig"]["futureMember"] == "preserved"
    assert rewritten["issuance"]["futureMember"] == "preserved"


@pytest.mark.parametrize(
    "change",
    [
        lambda raw: dict(raw, schemaVersion=2),
        lambda raw: dict(raw, phase="future"),
        lambda raw: dict(raw, name="\ud800"),
        lambda raw: dict(raw, creationInput={}),
        lambda raw: dict(raw, initialPublicKey={**raw["initialPublicKey"], "d": "private"}),
    ],
)
def test_corrupt_documents_cannot_be_imported(setup, change):
    _, store, arguments = setup
    with create("billing-agent", **arguments):
        pass
    document = change(saved(store))
    with pytest.raises(FoundryStateError):
        recovery_document(json.dumps(document).encode())
    with pytest.raises(FoundryStateError):
        recovery_document(b'{"schemaVersion":1,"schemaVersion":1}')


def _hold_process_lock(directory, key, ready, release):
    store = FileFoundryStore(directory)
    with store.lock(key):
        ready.set()
        release.wait(10)


def test_cross_process_lock_waits_to_deadline(setup):
    server, store, arguments = setup
    with create("billing-agent", **arguments):
        pass
    context = multiprocessing.get_context("spawn")
    ready, release = context.Event(), context.Event()
    key = (server._base_url, ORG, "billing-agent")
    process = context.Process(
        target=_hold_process_lock, args=(store.directory, key, ready, release)
    )
    process.start()
    try:
        assert ready.wait(10)
        with pytest.raises(FoundryBusy):
            with verification_budget(0.05), FileFoundryStore(store.directory).lock(key):
                pytest.fail("competing process acquired the lock")
    finally:
        release.set()
        process.join(10)
        if process.is_alive():
            process.terminate()
    assert process.exitcode == 0


def test_write_requires_lock_and_missing_state_is_not_recreated(setup):
    server, store, arguments = setup
    identity = create("billing-agent", **arguments)
    key = (server._base_url, ORG, "billing-agent")
    with pytest.raises(FoundryStateError):
        store.save(key, saved(store))
    store._path(key).unlink()
    with pytest.raises(FoundryStateError):
        identity.active()
    assert len(server.created) == 1
    identity.close()


def test_integrity_failure_after_submission_stops_without_retry(setup):
    from dnsid.enums import VerificationCode
    from dnsid.exceptions import VerificationError

    server, _, arguments = setup
    server.submit_error = VerificationError(
        VerificationCode.RECORD_INVALID, "receipt hash mismatch"
    )
    with create("billing-agent", **arguments) as identity:
        with pytest.raises(FoundryError):
            identity.active()
        assert len(server.submitted) == server.prepare_calls == 1
        server.reader._load_complete_history.assert_not_called()
        with pytest.raises(SigningPaused):
            identity.sign(b"invalid")


def test_core_does_not_reexport_foundry_create():
    assert not hasattr(dnsid, "FoundryIdentity")
    assert not hasattr(dnsid, "create")


@pytest.mark.parametrize(
    "boundary",
    [
        "creation-intent",
        "identity-known",
        "proof-signature",
        "proof-submitting",
        "publication",
        "entity",
        "issuance-intent",
        "issuance-prepared",
        "completed-bytes",
        "submitting",
        "accepted",
        "public-completion",
        "handle-complete",
    ],
)
def test_interruption_at_each_durable_boundary(setup, boundary):
    server, store, arguments = setup
    server.proof_required = True
    server.status = "VERIFICATION"
    save = store.save
    failures = []

    def interrupted(key, document):
        issuance = document.get("issuance", {})
        proof = document.get("proof", {})
        conditions = {
            "creation-intent": "identityId" not in document,
            "identity-known": "identityId" in document,
            "proof-signature": "signature" in proof and proof.get("submissionState") == "prepared",
            "proof-submitting": proof.get("submissionState") == "submitting",
            "publication": "publicationConfig" in document,
            "entity": "entityPublicKey" in document,
            "issuance-intent": bool(issuance),
            "issuance-prepared": "preparedEntryBytes" in issuance,
            "completed-bytes": "entryBytes" in issuance,
            "submitting": issuance.get("submission", {}).get("state") == "pending",
            "accepted": issuance.get("submission", {}).get("state") == "accepted",
            "public-completion": issuance.get("complete") is True,
            "handle-complete": document["phase"] == "complete",
        }
        if not failures and conditions[boundary]:
            failures.append(copy.deepcopy(document))
            raise OSError("interrupted durable boundary")
        save(key, document)

    store.save = interrupted
    try:
        with create("billing-agent", **arguments) as identity:
            identity.active()
    except FoundryError:
        pass
    assert failures
    store.save = save
    with create("billing-agent", **arguments) as identity:
        identity.active()
        assert identity.state == "ACTIVE"
    assert saved(store)["phase"] == "complete"
    assert len({key for _, key in server.created}) == 1
    assert all(request == server.created[0][0] for request, _ in server.created)
    assert len({(data, key) for _, data, key in server.submitted}) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("entryHash", "0" * 64),
        ("complete", "true"),
        ("activationBlocked", 0),
    ],
)
def test_complete_record_corruption_fails_before_signing_or_registry_read(setup, field, value):
    server, store, arguments = setup
    with create("billing-agent", **arguments) as identity:
        identity.active()
    key = (server._base_url, ORG, "billing-agent")
    document = saved(store)
    document["issuance"][field] = value
    store._path(key).write_bytes(canonical_bytes(document))
    server.get_registration = Mock(side_effect=AssertionError("must validate state first"))
    with pytest.raises(FoundryStateError):
        create("billing-agent", **arguments)
    assert len(server.created) == 1


def test_same_process_competitors_reopen_one_local_operation(setup):
    from concurrent.futures import ThreadPoolExecutor

    server, store, arguments = setup

    def competing_create(_):
        with create("billing-agent", **arguments) as identity:
            return identity.domain

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(competing_create, range(4))) == [DOMAIN] * 4
    assert len(server.created) == 1


def test_names_remain_exact_and_never_become_paths(setup):
    server, store, arguments = setup
    for name in ("../café ", "Agent", "agent", "cafe\u0301"):
        with create(name, **arguments):
            pass
        assert saved(store, name)["name"] == name
        assert server.created[-1][0].name == name
    assert len(list(store.directory.glob("*.json"))) == 4


def test_provider_without_cancellation_checked_after_call(setup):
    import time

    server, _, arguments = setup
    provider = arguments["key_provider"]
    original = provider.signing_key

    def slow():
        time.sleep(0.02)
        return original()

    provider.signing_key = slow
    with pytest.raises(FoundryDeadline):
        create("billing-agent", **arguments, timeout=0.005)
    assert not server.created


def test_unknown_proof_outcome_is_not_reissued_when_expired(setup):
    server, store, arguments = setup
    server.proof_required = server.proof_expired = True
    server.status = "VERIFICATION"
    with create("billing-agent", **arguments) as identity:
        key = (server._base_url, ORG, "billing-agent")
        with store.lock(key):
            document = store.load(key)
            proof = document["proof"]
            proof["signature"] = b64url_encode(
                arguments["key_provider"].sign(
                    b64url_decode_strict(proof["challengeMessage"]),
                )
            )
            proof["submissionState"] = "submitting"
            store.save(key, document)
        with pytest.raises(FoundryError) as caught:
            identity.active()
        assert caught.value.resumable
        assert not server.reissues and not server.proofs


@pytest.mark.parametrize("status", ["RETIRED", "REVOKED", "ERROR", "CANCELLED", "REJECTED"])
def test_initial_terminal_or_workflow_response_returns_typed_outcome(setup, status):
    server, store, arguments = setup
    server.status = status
    expected = TerminalIdentity if status in {"RETIRED", "REVOKED"} else WorkflowOutcome
    with pytest.raises(expected):
        create("billing-agent", **arguments)
    assert saved(store)["registryStatus"] == status
    assert not server.submitted


def test_profile_helper_pauses_with_manager_available_and_no_provider_read_per_signature(setup):
    from dnsid import JWTOptions
    from dnsid.jose import JoseProfile

    server, store, arguments = setup
    server.public_status = "PENDING"
    with create("billing-agent", **arguments) as identity:
        with pytest.raises(FoundryDeadline):
            identity.active(timeout=1.0)
        manager = identity.identity_manager()
        profile = JoseProfile.from_identity_manager(manager)
        with pytest.raises(SigningPaused):
            profile.create_jwt(JWTOptions(audience="peer.example.com"))
        server.public_status = "ACTIVE"
        identity.active()
        provider = arguments["key_provider"]
        provider.signing_key = Mock(wraps=provider.signing_key)
        identity.sign(b"one")
        profile.create_jwt(JWTOptions(audience="peer.example.com"))
        provider.signing_key.assert_not_called()
