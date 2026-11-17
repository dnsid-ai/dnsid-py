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
from dnsid._verification_budget import BudgetExhausted, remaining_seconds, verification_budget
from dnsid.c2sp_tlog import (
    C2spSignerRole,
    C2spTlogReader,
    C2spVerificationContext,
    entry_bytes,
    prepare_event,
    sign_prepared_event,
)
from dnsid.c2sp_tlog.canonical import canonical_bytes
from dnsid.enums import DNSSECState, VerificationCode
from dnsid.exceptions import RegistryRequestError, VerificationError
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
    PublicationConfig,
    TLSCertificate,
    TXTRecord,
)

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
                    {"revocationReason": "keyCompromise"}
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
        self.status = "PROVISIONING"
        self.dns_published = True
        self.replay_status = None
        self.public_status = "ACTIVE"
        self.public_gi = GI
        self.public_lr = LR
        self.omit_domain = False
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
        self.prepare_calls = 0
        self.submit_error = None
        self.lose_create = False
        self.competitor = False
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

    def register_live_agent(self, request, idempotency_key):
        self.created.append((request, idempotency_key))
        if request.public_key_jwk.thumbprint() != self.provider.signing_key().thumbprint():
            raise RegistryRequestError("/agent", 409, "KEY_MISMATCH")
        if self.lose_create:
            self.lose_create = False
            raise TimeoutError("lost create response")
        result = FoundryServer.get_registration(self, DOMAIN)
        result.registry_status = self.replay_status or self.status
        if self.omit_domain:
            result.domain = ""
        return result

    def get_registration(self, domain):
        assert domain == DOMAIN
        return AgentRegistration(
            DOMAIN,
            "registry",
            self.status,
            self._base_url,
            publication_config=self.publication,
            dns_published=self.dns_published,
            id="id-1",
        )

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
        self.status = "READY"
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
    vectors = [
        ("agent", "ksFWEjxU0Yf_F7-_UEwFWQ3J97VRmQPVLjVM5l-3YlY"),
        ("Agent", "43mRUDBHeMLHZ6AZKy6RTQXox_LZxBDLa3IXLQ0qCGI"),
        ("agent ", "eVX-4H-42OOxnU2EbgtKoEzYad0bIaaRoCkf5T2BIEM"),
        ("café", "kBdivhIHZhZ_20_Ku_KnIVYE7x0iSw4K1ceQb2s6fxs"),
        ("cafe\u0301", "WxS5QzyfB3D0utVhJDzJQTY6eXDMagDV3tqOImr_u6A"),
        ("\u00a0cafe\u0301\u3000", "x6ARjxrBFYbZ1jCSznnOWBUX9DpFr4edVmYy1zLnyTc"),
        ("😀" * 255, "AEttzAMd8C-GpyQqR_y5G-IfIawJpRWIMi4ZpfbkqWU"),
        ('a"b', "2bWVuTgcCN056vagU5cF40TRXcroeKQCLhd5hTVjhcM"),
        ("a\\b", "g8sOgOWQxkQncp1g_H2nI81dTe-60Y8p6ryb87s3Vrk"),
        ("a\u0001b", "oNMzk-Vz7VqZ75bxvj4srioM6Dtxd0lNFT3W_-uOF0A"),
        ("a\nb", "yM6te8_oTYfg8b2Co21WukeVw4SfYQgCG9brN_W9Bio"),
        ("<a>&", "D-ZrRgfx1r9BUVg-wF9Pbey_cfLsZjWeOUCRCsYhTnk"),
        ("a\u2028b", "-0mnonROfh4y6N--aNbASSi_x7pWEcBu8-Ldwmop4mU"),
        ("a\u007fb", "V9Xm6mXYXgQCT7DLYtBfT-etOMFRmX9mgKK60ocWtTA"),
        ("a/b", "vQvjQxYsTU1TyU3oai2SQY07iNjuCrSBPH5fCjHqhiE"),
    ]
    for name, expected in vectors:
        assert registration_key(ORG, name, initial) == expected


@pytest.mark.parametrize("name", ["", "\ud800", "\udfff", "😀" * 256, 5])
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
        assert identity.identity_manager().local_domain == DOMAIN
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


@pytest.mark.parametrize("error", [
    RegistryRequestError("/status", 401),
    RegistryRequestError("/status", 403),
    RegistryRequestError("/status", 429),
    VerificationError(VerificationCode.RECORD_INVALID, "invalid registry response"),
    UnsupportedContract("unsupported registry capability"),
])
def test_control_plane_reopen_failure_does_not_pause_completed_identity(setup, error):
    server, store, arguments = setup
    with create("billing-agent", **arguments) as identity:
        identity.active()
    before = saved(store)
    registration = server.get_registration
    server.get_registration = Mock(side_effect=error)
    with pytest.raises(FoundryError) as caught:
        create("billing-agent", **arguments)
    assert caught.value is error or caught.value.__cause__ is error
    assert not saved(store).get("signingPaused")
    assert saved(store) == before
    server.get_registration = registration
    with create("billing-agent", **arguments) as reopened:
        reopened.sign(b"after control-plane recovery")
    assert server.prepare_calls == len(server.submitted) == 1


def test_registry_key_mismatch_still_pauses_completed_identity(setup):
    server, store, arguments = setup
    with create("billing-agent", **arguments) as identity:
        identity.active()
    registration = server.get_registration
    server.get_registration = Mock(side_effect=RegistryRequestError("/status", 409, "KEY_MISMATCH"))
    with pytest.raises(KeyMismatch):
        create("billing-agent", **arguments)
    assert saved(store)["signingPaused"] is True
    server.get_registration = registration
    with create("billing-agent", **arguments) as reopened:
        with pytest.raises(SigningPaused):
            reopened.sign(b"unverified key mismatch")


def test_unsupported_publication_capability_does_not_pause_completed_identity(setup):
    server, store, arguments = setup
    with create("billing-agent", **arguments) as identity:
        identity.active()
        registration = server.get_registration(DOMAIN)
        registration.publication_authority = "client"
        server.get_registration = Mock(return_value=registration)
        with pytest.raises(UnsupportedContract):
            identity.active()
        assert not saved(store).get("signingPaused")
        identity.sign(b"unsupported capability is not a binding mismatch")


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


@pytest.mark.parametrize("missing", ["identityId", "domain"])
def test_partial_creation_replays_until_both_id_and_domain_are_saved(setup, missing):
    server, store, arguments = setup
    with create("billing-agent", **arguments):
        pass
    partial = saved(store)
    partial["phase"] = "creation-pending"
    partial.pop(missing)
    resumed = FileFoundryStore(store.directory.parent / "partial")
    resumed.import_operation(canonical_bytes(partial))
    arguments["store"] = resumed
    server.get_registration = Mock(wraps=server.get_registration)
    with create("billing-agent", **arguments) as identity:
        assert identity.domain == DOMAIN
    assert server.created[0] == server.created[1]
    assert saved(resumed)["identityId"] == "id-1" and saved(resumed)["domain"] == DOMAIN
    server.get_registration.assert_not_called()
    with create("billing-agent", **arguments):
        pass
    assert len(server.created) == 2
    server.get_registration.assert_called_once_with(DOMAIN)


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


@pytest.mark.parametrize("missing", [("gi",), ("governance_domain",), ("gi", "governance_domain")])
def test_absent_governance_onboarding_is_resumable_before_binding_comparison(setup, missing):
    server, _, arguments = setup
    for member in missing:
        server.onboarding.pop(member)
    arguments["config"].foundry = FoundryConfig("other-org", "other.example")
    with pytest.raises(WorkflowOutcome, match="organization onboarding is not ready") as caught:
        create("billing-agent", **arguments)
    assert caught.value.resumable
    assert not server.created


@pytest.mark.parametrize("body", [
    None, [], {}, {"org_id": ORG}, {"ek": {"status": "verified"}},
    {"org_id": ORG, "ek": {}},
])
def test_malformed_or_missing_required_onboarding_is_unsupported(setup, body):
    server, _, arguments = setup
    server.get_organization_onboarding = Mock(return_value=body)
    with pytest.raises(UnsupportedRegistry):
        create("billing-agent", **arguments)
    assert not server.created


@pytest.mark.parametrize("member", ["domain", "state", "gate_authorized"])
def test_present_incomplete_governance_proof_is_unsupported(setup, member):
    server, _, arguments = setup
    server.onboarding["gi"].pop(member)
    with pytest.raises(UnsupportedRegistry):
        create("billing-agent", **arguments)
    assert not server.created


def test_empty_provider_does_not_generate_or_select_a_key(setup):
    server, _, arguments = setup
    empty = Mock(spec=LocalKeyProvider)
    empty.list_key_ids.return_value = []
    arguments["key_provider"] = empty
    with pytest.raises(KeyMissing, match="create the key first"):
        create("billing-agent", **arguments)
    empty.list_key_ids.assert_called_once()
    empty.signing_key.assert_not_called()
    empty.generate_key.assert_not_called()
    assert not server.created


def test_wrong_key_saved_and_stateless_replica(setup):
    guidance = (
        "use the provider key this identity was created with; "
        "run one identity per cloud provider"
    )
    server, store, arguments = setup
    with create("billing-agent", **arguments):
        pass
    arguments["key_provider"] = LocalKeyProvider.generate()
    with pytest.raises(KeyMismatch) as caught:
        create("billing-agent", **arguments)
    assert caught.value.identity_id == "id-1" and len(server.created) == 1
    assert str(caught.value) == guidance
    arguments["store"] = FileFoundryStore(store.directory.parent / "replica")
    with pytest.raises(KeyMismatch) as caught:
        create("billing-agent", **arguments)
    assert caught.value.error_code == "KEY_MISMATCH"
    assert str(caught.value) == guidance


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
        assert saved(store)["signingPaused"] is True


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


@pytest.mark.parametrize("stage", ["preparation", "submission", "submission-exception"])
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
                server.status = "READY"
                raise RegistryRequestError("/prepare", 409, "TLOG_PREPARATION_MISMATCH")

            server.prepare_issuance = reject_prepare
        else:
            server.competitor = True
            if stage == "submission-exception":
                original_submit = server.submit_prepared_event

                def reject_submit(domain, data, key):
                    rejected = original_submit(domain, data, key)
                    raise RegistryRequestError("/submit", 422, rejected.error_code)

                server.submit_prepared_event = reject_submit
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


@pytest.mark.parametrize("stage", ["preparation", "submission", "submission-exception"])
@pytest.mark.parametrize(
    "status,code",
    [
        (401, "UNAUTHORIZED"),
        (403, "FORBIDDEN"),
        (404, "NOT_FOUND"),
        (401, "TLOG_INVALID_ENTRY"),
        (403, "TLOG_PREPARATION_MISMATCH"),
        (404, "IDEMPOTENCY_MISMATCH"),
        (400, "BAD_REQUEST"),
        (409, "OTHER_CONFLICT"),
    ],
)
def test_control_plane_errors_do_not_reject_issuance_or_trigger_log_recovery(
    setup, stage, status, code
):
    server, store, arguments = setup
    method = "prepare_issuance" if stage == "preparation" else "submit_prepared_event"
    original = getattr(server, method)
    if stage == "submission":
        failure = Mock(
            return_value=SubmissionResult("rejected", error_code=code, status_code=status)
        )
    else:
        failure = Mock(side_effect=RegistryRequestError("/issuance", status, code))
    setattr(server, method, failure)
    with create("billing-agent", **arguments) as identity:
        with pytest.raises(FoundryError) as caught:
            identity.active()
        assert caught.value.status_code == status and caught.value.error_code == code
        assert caught.value.resumable
        server.reader._load_complete_history.assert_not_called()
        record = saved(store)["issuance"]
        assert not record["terminalFailure"] and "serverRejection" not in record
        assert record.get("submission", {}).get("state") != "rejected"
        assert record["requestError"] == {"httpStatus": status, "errorCode": code}
        completed = record.get("entryBytes")
        setattr(server, method, original)
        identity.active()
        assert saved(store)["phase"] == "complete"
        if completed:
            assert saved(store)["issuance"]["entryBytes"] == completed
    assert len(server.created) == 1 and len(server.submitted) == 1


@pytest.mark.parametrize("phase", ["registry", "issuance", "public"])
def test_polling_backoff_doubles_from_one_second_and_caps_at_fifteen(setup, monkeypatch, phase):
    import dnsid.foundry._workflow as workflow

    server, _, arguments = setup
    delays = []
    monkeypatch.setattr(workflow.time, "sleep", delays.append)
    attempts = 0
    if phase == "registry":
        original = server.get_registration

        def registration(domain):
            nonlocal attempts
            attempts += 1
            server.dns_published = attempts > 6
            return original(domain)

        server.get_registration = registration
    elif phase == "issuance":
        original = server.submit_prepared_event

        def submit(domain, data, key):
            nonlocal attempts
            attempts += 1
            if attempts <= 6:
                return SubmissionResult(
                    "pending", error_code="TLOG_SUBMISSION_BUSY", status_code=202,
                )
            return original(domain, data, key)

        server.submit_prepared_event = submit
    else:
        original = server.https.fetch_strict_json

        def fetch(url, *args, **kwargs):
            nonlocal attempts
            if url.endswith("/status"):
                attempts += 1
                server.public_status = "PENDING" if attempts <= 6 else "ACTIVE"
            return original(url, *args, **kwargs)

        server.https.fetch_strict_json = fetch
    with create("billing-agent", **arguments) as identity:
        identity.active()
    assert attempts == (9 if phase == "registry" else 7)
    assert delays == [1.0, 2.0, 4.0, 8.0, 15.0, 15.0]


def test_default_deadlines_and_poll_sleep_use_the_remaining_budget(monkeypatch):
    import inspect

    import dnsid.foundry._workflow as workflow

    assert inspect.signature(create).parameters["timeout"].default == 30.0
    assert inspect.signature(workflow.FoundryIdentity.active).parameters["timeout"].default == 600.0
    remaining = Mock(side_effect=[0.25, 0.2])
    sleep = Mock()
    monkeypatch.setattr(workflow, "remaining_seconds", remaining)
    monkeypatch.setattr(workflow.time, "sleep", sleep)
    assert workflow._sleep(8.0) == 15.0
    sleep.assert_called_once_with(0.25)
    assert remaining.call_args_list[0].args == (8.0,)
    assert remaining.call_args_list[1].args == ()


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
    assert server.prepare_calls == len(server.submitted) == 1
    assert len(server.created) == 2 and server.created[0] == server.created[1]


@pytest.mark.parametrize("saved_issuance", [False, True])
@pytest.mark.parametrize("empty_result", [False, True])
def test_ready_issuance_recovery_waits_for_log_visibility(setup, saved_issuance, empty_result):
    from dnsid.c2sp_tlog.errors import C2spTlogVerificationError

    server, store, arguments = setup
    with create("billing-agent", **arguments) as identity:
        identity.active()
    if not saved_issuance:
        arguments["store"] = FileFoundryStore(store.directory.parent / "replica")
    original_load = server.load_history
    server.reader._load_complete_history.side_effect = (
        (lambda *a, **kw: SimpleNamespace(current_stream_events=[]))
        if empty_result else C2spTlogVerificationError("lifecycle contains no ISSUANCE event")
    )
    with create("billing-agent", **arguments) as identity:
        with pytest.raises(FoundryError) as caught:
            identity.active()
        assert caught.value.resumable
        assert server.prepare_calls == len(server.submitted) == 1
        server.reader._load_complete_history.side_effect = original_load
        identity.active()
    assert server.prepare_calls == len(server.submitted) == 1


@pytest.mark.parametrize("stage", ["preparation", "submission", "submission-exception"])
@pytest.mark.parametrize("empty_result", [False, True])
def test_invalid_entry_stays_resumable_with_registry_code(setup, stage, empty_result):
    from dnsid.c2sp_tlog.errors import C2spTlogVerificationError

    server, store, arguments = setup
    if stage == "preparation":
        server.prepare_issuance = Mock(
            side_effect=RegistryRequestError("/prepare", 422, "TLOG_INVALID_ENTRY"),
        )
    elif stage == "submission":
        server.submit_prepared_event = Mock(return_value=SubmissionResult(
            "rejected", error_code="TLOG_INVALID_ENTRY", status_code=422,
        ))
    else:
        server.submit_prepared_event = Mock(
            side_effect=RegistryRequestError("/submit", 422, "TLOG_INVALID_ENTRY"),
        )
    server.reader._load_complete_history.side_effect = (
        (lambda *a, **kw: SimpleNamespace(current_stream_events=[]))
        if empty_result else C2spTlogVerificationError("lifecycle contains no ISSUANCE event")
    )
    for _ in range(2):
        with create("billing-agent", **arguments) as identity:
            with pytest.raises(FoundryError) as caught:
                identity.active()
            assert caught.value.resumable
            assert caught.value.error_code == "TLOG_INVALID_ENTRY"
            assert caught.value.status_code == 422
        if stage != "preparation":
            assert saved(store)["issuance"]["entryBytes"]
    method = server.prepare_issuance if stage == "preparation" else server.submit_prepared_event
    assert method.call_count == 1


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


@pytest.mark.parametrize("evidence", ["valid", "missing-rotation", "wrong-ku"])
def test_stateless_replica_after_rotation_recovers_initial_issuance(setup, evidence):
    from dnsid.c2sp_tlog import C2spChain, parse_prepared_issuance
    from dnsid.c2sp_tlog.event_codec import parse_c2sp_event_entry
    from dnsid.c2sp_tlog.stream_verifier import state_hash
    from dnsid.models import KeyRotationEvent

    server, store, arguments = setup
    original = arguments["key_provider"]
    with create("billing-agent", **arguments) as identity:
        identity.active()
    rotated = LocalKeyProvider.generate()
    previous = original.signing_key()
    current = rotated.signing_key()
    context = C2spVerificationContext(
        fqdn=DOMAIN, entity_key=server.entity.signing_key(),
        previous_operational_key=previous, operational_key=current,
    )
    issuance = parse_prepared_issuance(server.history[0].data, C2spVerificationContext())
    rotation = prepare_event(
        KeyRotationEvent(
            domain=DOMAIN, previous_kid=previous.kid,
            previous_thumbprint=previous.thumbprint(), new_kid=current.kid,
            new_thumbprint=current.thumbprint(), new_public_key=current,
            timestamp=datetime.datetime(2026, 11, 2, tzinfo=datetime.UTC),
        ),
        LR,
        C2spChain(1, issuance.event_id, state_hash({
            "fqdn": DOMAIN, "status": "ACTIVE",
            "entity_thumb": server.entity.signing_key().thumbprint(),
            "operational_thumb": previous.thumbprint(),
        })),
    )
    rotation = sign_prepared_event(rotation, C2spSignerRole.PREVIOUS_OPERATIONAL, original, context)
    rotation = sign_prepared_event(rotation, C2spSignerRole.NEW_OPERATIONAL, rotated, context)
    data = entry_bytes(rotation, context)
    if evidence != "missing-rotation":
        server.history.append(SimpleNamespace(index=1, data=data, event=parse_c2sp_event_entry(data)))
    server.provider = rotated
    server.public_provider = original if evidence == "wrong-ku" else rotated
    server.replay_status = "provider_deferred"
    arguments["key_provider"] = rotated
    replica = FileFoundryStore(store.directory.parent / "rotated-replica")
    arguments["store"] = replica
    with create("billing-agent", **arguments) as identity:
        with pytest.raises(SigningPaused):
            identity.sign(b"before active")
        if evidence == "valid":
            identity.active()
            assert current.verify(b"replica", identity.sign(b"replica"))
            document = saved(replica)
            assert document["initialPublicKey"] == previous.to_dict()
            assert document["currentPublicKey"] == current.to_dict()
            assert document["creationInput"]["public_key"] == current.to_dict()
            assert document["registrationKey"] == registration_key(ORG, "billing-agent", current.thumbprint())
            assert b64url_decode_strict(document["issuance"]["entryBytes"]) == server.history[0].data
        else:
            with pytest.raises(FoundryError):
                identity.active()
            with pytest.raises(SigningPaused):
                identity.sign(b"unverified")
    if evidence == "valid":
        with create("billing-agent", **arguments) as identity:
            identity.sign(b"restart")
            identity.active()
        partial = saved(replica)
        partial["phase"] = "creation-pending"
        partial.pop("identityId")
        replay = FileFoundryStore(store.directory.parent / "partial-rotated-replica")
        replay.import_operation(canonical_bytes(partial))
        arguments["store"] = replay
        with create("billing-agent", **arguments) as identity:
            identity.active()
        assert server.created[2] == server.created[1]
    assert len(server.created) == (3 if evidence == "valid" else 2)
    assert server.created[0][1] != server.created[1][1]
    assert server.prepare_calls == len(server.submitted) == 1


def test_foundry_config_is_loader_owned_and_validated_by_the_facade(setup):
    from dnsid.exceptions import ArgumentError

    server, _, arguments = setup
    assert FoundryConfig.__module__ == "dnsid.config_loading"
    arguments["config"].foundry = {"organizationId": ORG}
    with pytest.raises(ArgumentError, match="config.foundry must be a FoundryConfig"):
        create("billing-agent", **arguments)
    assert not server.created


@pytest.mark.parametrize("state", ["REVOKED", "RETIRED"])
@pytest.mark.parametrize("source", ["registry", "public", "log"])
def test_terminal_observation_stays_paused_after_restart(setup, state, source):
    server, store, arguments = setup
    with create("billing-agent", **arguments) as identity:
        identity.active()
        manager = identity.identity_manager()
        if source == "registry":
            server.status = state
        elif source == "public":
            server.public_status = state
        else:
            server.reader.verify_non_revocation.return_value.logged_state = state
        with pytest.raises(TerminalIdentity):
            identity.active()
        assert saved(store)["registryStatus"] == state
        assert saved(store)["signingPaused"] is True
        with pytest.raises(SigningPaused):
            manager.key_provider.sign(b"profile")
        server.status = "READY"
        server.public_status = "ACTIVE"
        server.reader.verify_non_revocation.return_value.logged_state = "ACTIVE"
        with pytest.raises(TerminalIdentity):
            identity.active()
    with pytest.raises(TerminalIdentity):
        create("billing-agent", **arguments)
    assert server.prepare_calls == len(server.submitted) == len(server.created) == 1


def test_mismatch_pause_survives_restart_until_active_verifies_again(setup):
    server, store, arguments = setup
    with create("billing-agent", **arguments) as identity:
        identity.active()
        server.public_provider = LocalKeyProvider.generate()
        with pytest.raises(KeyMismatch):
            identity.active()
        assert saved(store)["phase"] == "complete"
        assert saved(store)["signingPaused"] is True
        with pytest.raises(SigningPaused):
            identity.sign(b"mismatch")
    server.public_provider = arguments["key_provider"]
    with create("billing-agent", **arguments) as identity:
        with pytest.raises(SigningPaused):
            identity.identity_manager().key_provider.sign(b"restart")
        assert saved(store)["signingPaused"] is True
        identity.active()
        identity.sign(b"verified")
        assert saved(store)["signingPaused"] is False
    with create("billing-agent", **arguments) as identity:
        identity.sign(b"second restart")
    assert server.prepare_calls == len(server.submitted) == len(server.created) == 1


@pytest.mark.parametrize("observation", ["mismatch", "terminal"])
@pytest.mark.parametrize("expiry", ["deadline", "cancellation"])
def test_confirmed_pause_survives_caller_budget_and_restart(setup, monkeypatch, observation, expiry):
    server, store, arguments = setup
    with create("billing-agent", **arguments) as identity:
        identity.active()
        clock = [100.0]
        monkeypatch.setattr("dnsid._verification_budget.time.monotonic", lambda: clock[0])
        cancelled = threading.Event()

        def spend_budget():
            if expiry == "deadline":
                clock[0] += 2.0
            else:
                cancelled.set()
            with pytest.raises(BudgetExhausted):
                remaining_seconds()

        if observation == "mismatch":
            server.public_provider = LocalKeyProvider.generate()
            check_public = identity._facade.check_public

            def observe(*args):
                spend_budget()
                check_public(*args)

            monkeypatch.setattr(identity._facade, "check_public", observe)
            expected = KeyMismatch
        else:
            def observe(*args):
                spend_budget()
                return SimpleNamespace(logged_state="RETIRED")

            server.reader.verify_non_revocation.side_effect = observe
            expected = TerminalIdentity
        save = store.save
        pause_budgets = []

        def save_pause(key, operation):
            if operation.get("signingPaused"):
                pause_budgets.append(remaining_seconds(10.0))
            save(key, operation)

        monkeypatch.setattr(store, "save", save_pause)
        with pytest.raises(expected):
            identity.active(timeout=1.0, cancelled=cancelled)
        assert pause_budgets == [5.0]
        assert saved(store)["signingPaused"] is True
        with pytest.raises(SigningPaused):
            identity.sign(b"expired observation")
    if observation == "terminal":
        with pytest.raises(TerminalIdentity):
            create("billing-agent", **arguments)
    else:
        with create("billing-agent", **arguments) as reopened:
            with pytest.raises(SigningPaused):
                reopened.sign(b"restart")


def test_pause_write_failure_keeps_original_observation_error(setup, monkeypatch):
    server, store, arguments = setup
    with create("billing-agent", **arguments) as identity:
        identity.active()
        server.public_provider = LocalKeyProvider.generate()
        save = store.save

        def fail_pause(key, operation):
            if operation.get("signingPaused"):
                raise OSError("pause storage unavailable")
            save(key, operation)

        monkeypatch.setattr(store, "save", fail_pause)
        with pytest.raises(KeyMismatch) as caught:
            identity.active()
        assert any("pause storage unavailable" in note for note in caught.value.__notes__)
        with pytest.raises(SigningPaused):
            identity.sign(b"failed pause write")


def test_ordinary_store_save_still_fails_after_budget_expiry(setup, monkeypatch):
    server, store, arguments = setup
    with create("billing-agent", **arguments):
        pass
    document = saved(store)
    clock = [100.0]
    monkeypatch.setattr("dnsid._verification_budget.time.monotonic", lambda: clock[0])
    key = (server._base_url, ORG, "billing-agent")
    with store.lock(key):
        with pytest.raises(BudgetExhausted):
            with verification_budget(1.0):
                clock[0] += 2.0
                with pytest.raises(BudgetExhausted):
                    store.save(key, {**document, "lateWrite": True})
    assert saved(store) == document


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
        lambda raw: dict(raw, schemaVersion=1),
        lambda raw: dict(raw, phase="future"),
        lambda raw: dict(raw, name="\ud800"),
        lambda raw: dict(raw, creationInput={}),
        lambda raw: dict(raw, signingPaused="false"),
        lambda raw: dict(raw, initialPublicKey=LocalKeyProvider.generate().signing_key().to_dict()),
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

    server, store, arguments = setup
    server.submit_error = VerificationError(
        VerificationCode.RECORD_INVALID, "receipt hash mismatch"
    )
    with create("billing-agent", **arguments) as identity:
        for _ in range(2):
            with pytest.raises(FoundryError):
                identity.active()
        assert saved(store)["issuance"]["terminalFailure"] is True
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
    save = store.save
    failures = []

    def interrupted(key, document):
        issuance = document.get("issuance", {})
        conditions = {
            "creation-intent": "identityId" not in document,
            "identity-known": "identityId" in document,
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


def test_only_second_completion_write_fails_then_active_resumes(setup, monkeypatch):
    server, store, arguments = setup
    save = store.save
    completion_writes = []

    def fail_second_completion(key, document):
        issuance = document.get("issuance", {})
        if issuance.get("complete"):
            completion_writes.append(copy.deepcopy(issuance))
            if len(completion_writes) == 2:
                assert not issuance["activationBlocked"]
                raise OSError("second completion write failed")
        save(key, document)

    monkeypatch.setattr(store, "save", fail_second_completion)
    with create("billing-agent", **arguments) as identity:
        with pytest.raises(FoundryError):
            identity.active()
        interrupted = saved(store)
        assert completion_writes[0]["activationBlocked"]
        assert interrupted["issuance"]["complete"]
        assert interrupted["issuance"]["activationBlocked"]
        assert interrupted["phase"] == "issuance-accepted"
        with pytest.raises(SigningPaused):
            identity.sign(b"paused")
        identity.active()
        completed = saved(store)
        assert completed["phase"] == "complete"
        assert completed["issuance"]["complete"]
        assert not completed["issuance"]["activationBlocked"]
        assert arguments["key_provider"].signing_key().verify(b"active", identity.sign(b"active"))
    assert len(server.created) == server.prepare_calls == len(server.submitted) == 1


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
