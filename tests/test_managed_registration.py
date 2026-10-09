"""Managed setup ordering, real public signatures, and recovery without replacement."""

import datetime
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from dnsid import (
    AgentRegistration,
    AgentRegistrationInput,
    DnsIdTxtRecord,
    FileRegistrationStore,
    IdentityManagerDependencies,
    LoadedConfig,
    LocalKeyProvider,
    ManagedRegistrationConfig,
    ManagedRegistrationError,
    PublicationConfig,
    RegistryAgentStatus,
    RegistryClient,
    load_file,
    merge_loaded_config,
    register_managed_identity,
)
from dnsid import managed_registration as workflow
from dnsid._utils import b64url_encode
from dnsid.c2sp_tlog import C2spSignerRole, canonical_bytes, prepare_event, sign_prepared_event
from dnsid.c2sp_tlog.event_codec import c2sp_envelope_to_event
from dnsid.enums import VerificationCode
from dnsid.exceptions import ArgumentError, RegistryRequestError, VerificationError
from dnsid.interfaces import LogReader
from dnsid.models import (
    IssuanceEvent,
    KeyRotationEvent,
    LoggedStateEvidence,
    LogRef,
    PreparedRegistryEvent,
    SubmissionResult,
    TLSCertificate,
    TXTRecord,
)
from dnsid.registry import LogRegistry
from tests.conftest import MockDNSResolver

DOMAIN = "agent.other.test"
GI = "entity.test"
EK = "https://dnsid.entity.test/ek.json"
LR = "c2sp-tlog:public:https://log.test#instance-1"
ORG = "11111111-1111-4111-8111-111111111111"
NAME = "billing-agent"
NOW = datetime.datetime.now(datetime.UTC).replace(microsecond=0) - datetime.timedelta(seconds=2)


class Setup:
    def __init__(self, tmp_path):
        self.store = FileRegistrationStore(tmp_path / "identity").select(
            "https://registry.test",
            ORG,
            NAME,
        )
        self.entity = LocalKeyProvider.generate()
        self.operational = None
        self.history = []
        self.loaded = LoadedConfig(registration=ManagedRegistrationConfig(GI, EK, ORG))
        self.loaded.registry.registry_url = "https://registry.test"
        self.loaded.dnsid.verification.trusted_entities = []
        self.publication = PublicationConfig(
            "dnsid-draft-01",
            GI,
            f"https://{DOMAIN}/ku.json",
            EK,
            LR,
            f"https://{DOMAIN}/status",
        )
        self.registration = AgentRegistration(
            DOMAIN,
            "registry",
            "VERIFIED",
            "https://registry.test",
            False,
            publication_config=self.publication,
            id="immutable-1",
        )
        self.status = RegistryAgentStatus("VERIFIED", False, None, True, False, False, False)
        self.entry = None
        self.client = Mock(spec=RegistryClient)
        self.client._base_url = "https://registry.test"
        self.client.register_agent.side_effect = self.register
        self.client.prepare_issuance.side_effect = self.prepare
        self.client.submit_prepared_event.side_effect = self.submit
        self.client.get_registration.return_value = self.registration
        self.client.get_agent_detail.side_effect = lambda domain: self.registration
        self.client.get_agent_status.return_value = self.status
        self.client.wait_for_status.return_value = self.status
        self.dns = MockDNSResolver()
        self.fetcher = Mock()
        self.fetcher.fetch_strict_json.side_effect = self.fetch
        self.reader = Mock(spec=LogReader)
        self.reader.verify_bilateral_binding.side_effect = self.bilateral
        self.reader.recover_issuance.side_effect = lambda domain, entity: (
            self.entry,
            LogRef.parse(f"{LR}@0"),
        )
        self.reader.rebuild_history.side_effect = lambda domain: self.history
        self.reader.verify_non_revocation.side_effect = lambda domain, at: LoggedStateEvidence(
            LR,
            "ACTIVE",
            f"{LR}@0",
            f"{LR}@{len(self.history) - 1}",
            1,
            "test",
            object(),
            at,
        )
        self.logs = LogRegistry()
        self.logs.register("c2sp-tlog", lambda lr: self.reader)
        self.deps = IdentityManagerDependencies(
            log_registry=self.logs,
            dns_resolver=self.dns,
            https_fetcher=self.fetcher,
        )

    def saved(self):
        return json.loads((self.store.directory / "registration.json").read_text())

    def register(self, request, key):
        saved = self.saved()
        from dnsid.managed_registration import _replay_keys

        assert saved["version"] == 3
        assert _replay_keys(saved)[0] == key != _replay_keys(saved)[1]
        assert request.name == NAME
        assert request.public_key_jwk.to_dict() == saved["initial_key"]
        assert '"d":' not in json.dumps(saved)
        if self.operational is None:
            self.operational = LocalKeyProvider.load(saved["key_locator"])
        return self.registration

    def prepare(self, domain, key):
        assert self.saved()["issuance"] is not None
        event = IssuanceEvent(
            domain=DOMAIN,
            governance_id=GI,
            timestamp=NOW,
            entity_key=self.entity.signing_key(),
            operational_key=self.operational.signing_key(),
        )
        prepared = sign_prepared_event(prepare_event(event, LR), C2spSignerRole.ENTITY, self.entity)
        return PreparedRegistryEvent(canonical_bytes(prepared.envelope), LR)

    def submit(self, domain, entry, key):
        import base64

        saved = self.saved()["issuance"]
        assert base64.b64decode(saved["entry"]) == entry
        assert saved["prepared_entry"]
        self.entry = entry
        self.registration.dns_published = True
        self.status = RegistryAgentStatus("READY", True, None, True, True, False, False)
        self.client.get_agent_status.return_value = self.status
        self.client.wait_for_status.return_value = self.status
        self.history = [c2sp_envelope_to_event(json.loads(entry))]
        self.publish()
        return SubmissionResult(
            "accepted", hashlib.sha256(entry).hexdigest(), 0, LogRef.parse(f"{LR}@0")
        )

    def publish(self):
        record = DnsIdTxtRecord(
            v=self.publication.publish_profile,
            gi=GI,
            ek=EK,
            ku=self.publication.ku_url,
            su=self.publication.status_url,
            lr=LR,
            identity_fqdn=DOMAIN,
        )
        record.sg = b64url_encode(self.entity.sign(record.canonical().encode("ascii")))
        self.dns._records[f"_dnsid.{DOMAIN}"] = [TXTRecord([record.serialize().encode()], 300)]

    def fetch(self, url, **kwargs):
        cert = TLSCertificate(not_after=NOW + datetime.timedelta(days=1))
        if url == EK:
            return {"keys": [self.entity.signing_key().to_dict()]}, cert
        if url == self.publication.ku_url:
            return {"keys": [self.operational.signing_key().to_dict()]}, cert
        assert url == self.publication.status_url
        return {"state": "ACTIVE", "lastTransitionAt": NOW.isoformat()}, cert

    def bilateral(self, record, entity, operational):
        return SimpleNamespace(
            initial_operational_thumbprint=self.history[0].operational_key.thumbprint(),
            initial_entity_thumbprint=self.entity.signing_key().thumbprint(),
            timestamp=NOW,
        )

    def run(self, **kwargs):
        with patch.object(workflow, "RegistryClient", return_value=self.client):
            return register_managed_identity(
                kwargs.pop("name", NAME),
                self.loaded,
                "secret-not-persisted",
                self.store,
                deps=self.deps,
                log_registry_reference="test-trust-v1",
                interval=0.001,
                **kwargs,
            )


def test_fresh_setup_and_completed_resume_preserve_application_policy(tmp_path):
    setup = Setup(tmp_path)
    result = setup.run()
    assert result.registration.id == "immutable-1"
    assert result.logged_state_evidence.logged_state == "ACTIVE"
    assert setup.saved()["complete"] is True
    assert "secret-not-persisted" not in json.dumps(setup.saved())
    with pytest.raises(VerificationError) as denied:
        result.manager.verify_domain(DOMAIN)
    assert denied.value.code == VerificationCode.COUNTERPARTY_NOT_ACCEPTED
    result.manager.close()
    setup.run().manager.close()
    assert setup.client.register_agent.call_count == 1
    assert setup.client.prepare_issuance.call_count == 1
    assert setup.client.submit_prepared_event.call_count == 1
    assert setup.client.close.call_count == 2


def test_failed_setup_closes_owned_registry_client(tmp_path):
    setup = Setup(tmp_path)
    setup.client.register_agent.side_effect = RuntimeError("registry unavailable")
    with pytest.raises(ManagedRegistrationError):
        setup.run()
    setup.client.close.assert_called_once()


def test_configuration_file_and_merge_keep_setup_outside_core(tmp_path):
    path = tmp_path / "deployment.json"
    path.write_text(json.dumps({"registration": {"governanceId": GI, "entityKeyUrl": EK}}))
    loaded = load_file(path)
    assert loaded.registration == ManagedRegistrationConfig(GI, EK)
    assert loaded.dnsid.identity is None
    merged = merge_loaded_config(
        loaded, LoadedConfig(registration=ManagedRegistrationConfig("other.test"))
    )
    assert merged.registration == ManagedRegistrationConfig("other.test", EK)
    for raw in ({"registration": {"credential": "no"}}, {"registration": {"governanceId": 42}}):
        path.write_text(json.dumps(raw))
        with pytest.raises(ArgumentError):
            load_file(path)


def test_selector_contradiction_precedes_key_and_network(tmp_path):
    setup = Setup(tmp_path)
    with pytest.raises(ArgumentError):
        setup.run(input=AgentRegistrationInput(governance_domain="other.test"))
    assert not setup.store.key_path.exists()
    setup.client.register_agent.assert_not_called()


def test_busy_and_process_lock_recovery(tmp_path):
    first = FileRegistrationStore(tmp_path / "store")
    second = FileRegistrationStore(tmp_path / "store")
    with first.exclusive():
        for store in (first, second):
            with pytest.raises(ManagedRegistrationError, match="busy"):
                with store.exclusive():
                    pass
    with second.exclusive():
        second.save({"marker": 1})
        assert second.load() == {"marker": 1}
    assert first.directory.stat().st_mode & 0o777 == 0o700
    assert (first.directory / "registration.json").stat().st_mode & 0o777 == 0o600


def test_unknown_creation_reuses_complete_request_and_key(tmp_path):
    setup = Setup(tmp_path)
    original = setup.register
    attempts = []

    def create(request, key):
        attempts.append((asdict(request), key))
        if len(attempts) == 1:
            raise VerificationError(VerificationCode.LOG_ERROR, "timeout", transient=True)
        return original(request, key)

    setup.client.register_agent.side_effect = create
    setup.run().manager.close()
    assert attempts[0] == attempts[1]
    assert (
        not {
            "request",
            "registration_key",
            "issuance_key",
            "policy",
            "first_attempt",
            "last_clock",
            "replay_deadline",
        }
        & setup.saved().keys()
    )


def interrupt_creation(setup):
    error = VerificationError(VerificationCode.LOG_ERROR, "stop")
    setup.client.register_agent.side_effect = error
    with pytest.raises(ManagedRegistrationError):
        setup.run()
    setup.client.register_agent.side_effect = setup.register


@pytest.mark.parametrize("change", ["request", "key_loss", "corrupt", "old_schema", "locator"])
def test_conflicts_never_allocate_replacement(tmp_path, change):
    setup = Setup(tmp_path)
    interrupt_creation(setup)
    kwargs = {}
    if change == "request":
        kwargs["input"] = AgentRegistrationInput(capabilities_url="https://other.test/capabilities")
    elif change == "key_loss":
        setup.store.key_path.unlink()
    else:
        state = setup.saved()
        if change == "old_schema":
            state["version"] = 1
        elif change == "locator":
            state["key_locator"] = str(tmp_path / "another-key.json")
        else:
            state["initial_key"] = LocalKeyProvider.generate().signing_key().to_dict()
        with setup.store.exclusive():
            setup.store.save(state)
    with pytest.raises(ManagedRegistrationError):
        setup.run(**kwargs)
    assert setup.client.register_agent.call_count == 1


@pytest.mark.parametrize("clock", [0, 10**12])
def test_unknown_creation_resumes_without_clock_or_retention_bound(tmp_path, monkeypatch, clock):
    setup = Setup(tmp_path)
    interrupt_creation(setup)
    request = setup.client.register_agent.call_args
    monkeypatch.setattr("time.time", lambda: clock)
    setup.run().manager.close()
    assert setup.client.register_agent.call_args == request
    assert setup.client.register_agent.call_count == 2


@pytest.mark.parametrize("boundary", ["prepared", "entry", "accepted", "complete"])
def test_interruption_at_issuance_and_completion_boundaries(tmp_path, boundary):
    setup = Setup(tmp_path)
    save = setup.store.save
    interrupted = False

    def fail(state):
        nonlocal interrupted
        save(state)
        issuance = state["issuance"] or {}
        reached = {
            "prepared": bool(issuance.get("prepared_entry")),
            "entry": bool(issuance.get("entry")),
            "accepted": bool(issuance.get("submission")),
            "complete": state["complete"],
        }[boundary]
        if reached and not interrupted:
            interrupted = True
            raise OSError("process interrupted")

    setup.store.save = fail
    with pytest.raises(ManagedRegistrationError):
        setup.run()
    setup.store.save = save
    setup.run().manager.close()
    assert setup.client.register_agent.call_count == 1
    assert setup.client.prepare_issuance.call_count == 1
    assert setup.client.submit_prepared_event.call_count == 1


def test_completed_rotation_does_not_need_old_private_key(tmp_path):
    setup = Setup(tmp_path)
    setup.run().manager.close()
    initial = setup.operational.signing_key()
    kid = setup.operational.generate_key()
    setup.operational.activate(kid)
    setup.operational.supersede(initial.kid)
    current = setup.operational.signing_key()
    setup.history.append(
        KeyRotationEvent(
            domain=DOMAIN,
            timestamp=NOW + datetime.timedelta(seconds=1),
            previous_thumbprint=initial.thumbprint(),
            new_thumbprint=current.thumbprint(),
            new_public_key=current,
        )
    )
    setup.publish()
    result = setup.run()
    assert result.manager._key_provider.signing_key().thumbprint() == current.thumbprint()
    result.manager.close()
    assert setup.client.register_agent.call_count == 1
    assert setup.client.submit_prepared_event.call_count == 1


def test_unexplained_key_change_and_terminal_public_status_fail_closed(tmp_path):
    setup = Setup(tmp_path)
    setup.run().manager.close()
    new = setup.operational.generate_key()
    setup.operational.activate(new)
    with pytest.raises(ManagedRegistrationError):
        setup.run()
    assert setup.client.submit_prepared_event.call_count == 1


def test_signature_failure_not_retried_and_creation_facts_survive(tmp_path):
    setup = Setup(tmp_path)
    sign = setup.entity.sign
    setup.entity.sign = Mock(
        side_effect=lambda payload: sign(payload) if payload.startswith(b"{") else b"x" * 64
    )
    with pytest.raises(ManagedRegistrationError) as caught:
        setup.run()
    assert caught.value.domain == DOMAIN
    assert caught.value.registration_id == "immutable-1"
    assert caught.value.phase == "public_verification"
    assert isinstance(caught.value.__cause__, VerificationError)
    assert caught.value.__cause__.code == VerificationCode.SIGNATURE_INVALID
    assert setup.client.submit_prepared_event.call_count == 1


def test_credential_replacement_and_server_authorization_preserve_operation(tmp_path, monkeypatch):
    setup = Setup(tmp_path)
    interrupt_creation(setup)
    original = setup.saved()
    credential = ""

    def client(base_url, *, api_key, transport_config):
        nonlocal credential
        credential = api_key
        return setup.client

    monkeypatch.setattr("dnsid.managed_registration.RegistryClient", client)

    def register(request, key):
        from dnsid.managed_registration import _replay_keys

        assert key == _replay_keys(original)[0]
        assert asdict(request) == asdict(setup.client.register_agent.call_args_list[0].args[0])
        if credential == "another-organization":
            raise RegistryRequestError("/api/v1/agent", 403, "FORBIDDEN")
        return setup.register(request, key)

    setup.client.register_agent.side_effect = register

    def run(token):
        return register_managed_identity(
            NAME,
            setup.loaded,
            token,
            setup.store,
            deps=setup.deps,
            log_registry_reference="test-trust-v1",
            interval=0.001,
        )

    with pytest.raises(ManagedRegistrationError) as denied:
        run("another-organization")
    assert denied.value.status_code == 403
    assert denied.value.error_code == "FORBIDDEN"
    assert setup.saved() == original
    setup.client.prepare_issuance.assert_not_called()
    run("replacement-owner-credential").manager.close()
    from dnsid.managed_registration import _replay_keys

    assert _replay_keys(setup.saved()) == _replay_keys(original)
    assert "replacement-owner-credential" not in json.dumps(setup.saved())


@pytest.mark.parametrize("field", ["id", "publication_config"])
def test_conflicting_creation_replay_preserves_known_facts(tmp_path, field):
    setup = Setup(tmp_path)
    error = VerificationError(VerificationCode.LOG_ERROR, "detail unavailable")
    error.registration_response = {
        "id": "immutable-1",
        "domain": DOMAIN,
        "publication_config": asdict(setup.publication),
    }
    setup.client.register_agent.side_effect = error
    with pytest.raises(ManagedRegistrationError):
        setup.run()
    original = setup.saved()
    if field == "id":
        setup.registration.id = "different-instance"
    else:
        setup.publication.log_ref = "c2sp-tlog:public:https://log.test#different-instance"
    setup.client.register_agent.side_effect = setup.register
    with pytest.raises(ManagedRegistrationError, match="creation_binding"):
        setup.run()
    assert setup.saved()["creation_facts"] == original["creation_facts"]
    assert setup.saved()["registration"] is None
    setup.client.prepare_issuance.assert_not_called()


@pytest.mark.parametrize("status, code", [(410, "RETIRED"), (422, "IDEMPOTENCY_MISMATCH")])
def test_terminal_creation_replay_does_not_allocate_replacement(tmp_path, status, code):
    setup = Setup(tmp_path)
    interrupt_creation(setup)
    original = setup.saved()
    setup.client.register_agent.side_effect = RegistryRequestError("/api/v1/agent", status, code)
    with pytest.raises(ManagedRegistrationError) as rejected:
        setup.run()
    assert rejected.value.status_code == status
    assert rejected.value.error_code == code
    assert not rejected.value.resumable
    assert setup.saved() == original
    setup.client.prepare_issuance.assert_not_called()
    assert setup.client.register_agent.call_count == 2
    assert (
        setup.client.register_agent.call_args_list[0]
        == setup.client.register_agent.call_args_list[1]
    )


def test_known_creation_facts_retained_after_detail_error(tmp_path):
    setup = Setup(tmp_path)
    error = VerificationError(VerificationCode.LOG_ERROR, "detail unavailable")
    error.registration_response = {
        "id": "immutable-1",
        "domain": DOMAIN,
        "publication_config": {
            name: value for name, value in asdict(setup.publication).items() if value
        },
        "oidc_issuer_url": "",
        "credential": "must-not-persist",
    }
    setup.client.register_agent.side_effect = error
    with pytest.raises(ManagedRegistrationError) as failed:
        setup.run()
    assert failed.value.domain == DOMAIN
    assert failed.value.registration_id == "immutable-1"
    assert "must-not-persist" not in json.dumps(setup.saved())
    setup.client.register_agent.side_effect = setup.register
    setup.operational = LocalKeyProvider.load(setup.store.key_path)
    setup.run().manager.close()
    assert setup.client.register_agent.call_count == 1


def test_conflicting_accepted_hash_stops_without_reissuing(tmp_path):
    setup = Setup(tmp_path)
    setup.run().manager.close()
    state = setup.saved()
    state["acceptance"]["entry_hash"] = "0" * 64
    with setup.store.exclusive():
        setup.store.save(state)
    setup.client.register_agent.reset_mock()
    with pytest.raises(ManagedRegistrationError):
        setup.run()
    setup.client.register_agent.assert_not_called()
    assert setup.client.submit_prepared_event.call_count == 1


def test_cancel_after_acceptance_preserves_state(tmp_path):
    import threading

    setup = Setup(tmp_path)
    cancelled = threading.Event()
    submit = setup.submit

    def cancel(domain, entry, key):
        result = submit(domain, entry, key)
        cancelled.set()
        return result

    setup.client.submit_prepared_event.side_effect = cancel
    with pytest.raises(ManagedRegistrationError):
        setup.run(cancelled=cancelled)
    assert setup.saved()["issuance"]["submission"]["state"] == "accepted"
    assert not setup.saved()["complete"]
    setup.run().manager.close()
    assert setup.client.submit_prepared_event.call_count == 1


def test_absent_txt_is_retried_but_multiple_records_are_not(tmp_path):
    setup = Setup(tmp_path)
    fetch = setup.dns.fetch_txt
    calls = 0

    def delayed(name):
        nonlocal calls
        calls += 1
        records, state = fetch(name)
        return ([] if calls == 1 else records), state

    setup.dns.fetch_txt = delayed
    setup.run().manager.close()
    assert calls >= 2
    record = setup.dns._records[f"_dnsid.{DOMAIN}"][0]
    setup.dns._records[f"_dnsid.{DOMAIN}"] = [record, record]
    with pytest.raises(ManagedRegistrationError) as failed:
        setup.run()
    assert not failed.value.resumable
    assert setup.client.submit_prepared_event.call_count == 1


def test_completed_terminal_identity_is_not_recreated(tmp_path):
    setup = Setup(tmp_path)
    setup.run().manager.close()
    fetch = setup.fetch

    def revoked(url, **kwargs):
        data, cert = fetch(url, **kwargs)
        if url == setup.publication.status_url:
            data = {**data, "state": "REVOKED", "revocationReason": "keyCompromise"}
        return data, cert

    setup.fetcher.fetch_strict_json.side_effect = revoked
    with pytest.raises(ManagedRegistrationError) as failed:
        setup.run()
    assert failed.value.category == "terminal_identity"
    assert setup.saved()["complete"]
    assert setup.client.register_agent.call_count == 1


def test_effective_registry_transport_and_budget_are_used(monkeypatch):
    import httpx

    from dnsid import TransportConfig, safe_transport, verification_budget

    config = TransportConfig(private_address_hosts=frozenset({"registry.test"}))
    seen = []

    def transport(actual, **kwargs):
        assert actual == config
        return httpx.MockTransport(
            lambda request: seen.append(request) or httpx.Response(200, json={"ok": True})
        )

    monkeypatch.setattr(safe_transport, "make_ssrf_safe_transport", transport)
    client = RegistryClient("https://registry.test", api_key="credential", transport_config=config)
    with verification_budget(0.5):
        assert client._post("/test") == {"ok": True}
    assert seen[0].headers["Authorization"] == "Bearer credential"
    assert seen[0].extensions["timeout"]["read"] <= 0.5


@pytest.mark.parametrize("key_written", [False, True])
def test_interrupted_key_initialization_is_not_replaced(tmp_path, monkeypatch, key_written):
    setup = Setup(tmp_path)
    load = LocalKeyProvider.load
    original_key = None

    def interrupted(path, **kwargs):
        nonlocal original_key
        if key_written:
            original_key = load(path, **kwargs).signing_key().thumbprint()
        raise OSError("interrupted key initialization")

    monkeypatch.setattr(LocalKeyProvider, "load", interrupted)
    with pytest.raises(ManagedRegistrationError):
        setup.run()
    setup.client.register_agent.assert_not_called()
    monkeypatch.setattr(LocalKeyProvider, "load", load)
    if key_written:
        result = setup.run()
        assert result.manager._key_provider.signing_key().thumbprint() == original_key
        result.manager.close()
    else:
        with pytest.raises(ManagedRegistrationError, match="ambiguous_key_creation"):
            setup.run()
        assert not setup.store.key_path.exists()
        setup.client.register_agent.assert_not_called()


def test_matching_local_snapshot_and_file_environment_config_resume_same_operation(tmp_path):
    from dnsid import load_environment

    setup = Setup(tmp_path)
    result = setup.run()
    identity = result.manager._config.identity
    result.manager.close()
    file = tmp_path / "deployment.json"
    file.write_text(
        json.dumps(
            {
                "registration": {"governanceId": GI, "entityKeyUrl": EK, "organizationId": ORG},
                "registry": {"registryUrl": "https://registry.test"},
                "dnsid": {"verification": {"trustedEntities": []}},
            }
        )
    )
    setup.loaded = load_file(file)
    setup.run().manager.close()
    environment = load_environment({"DNSID_REGISTRY_URL": "https://registry.test"})
    setup.loaded = merge_loaded_config(environment, setup.loaded)
    setup.loaded.dnsid.identity = identity
    setup.run().manager.close()
    assert setup.client.register_agent.call_count == 1


def test_initial_cancellation_is_typed_and_does_not_mutate(tmp_path):
    import threading

    setup = Setup(tmp_path)
    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(ManagedRegistrationError, match="deadline_or_cancelled"):
        setup.run(cancelled=cancelled)
    assert not setup.store.key_path.exists()
    setup.client.register_agent.assert_not_called()


@pytest.mark.parametrize("authority", ["client", "live"])
def test_unsupported_creation_is_retained_without_countersigning(tmp_path, authority):
    setup = Setup(tmp_path)
    if authority == "client":
        setup.registration.publication_authority = "client"
    else:
        setup.registration.raw["tier"] = "live"
    with pytest.raises(ManagedRegistrationError) as failed:
        setup.run()
    assert failed.value.domain == DOMAIN
    assert setup.saved()["registration"]["id"] == "immutable-1"
    setup.client.prepare_issuance.assert_not_called()
    with pytest.raises(ManagedRegistrationError):
        setup.run()
    assert setup.client.register_agent.call_count == 1


def test_pending_local_rotation_requires_rotation_recovery(tmp_path):
    setup = Setup(tmp_path)
    setup.run().manager.close()
    setup.operational.generate_key()
    with pytest.raises(ManagedRegistrationError, match="pending_rotation_recovery_required"):
        setup.run()
    assert setup.client.prepare_issuance.call_count == 1


@pytest.mark.parametrize(
    "configuration",
    [ManagedRegistrationConfig(), ManagedRegistrationConfig(GI, "http://entity.test/keys")],
)
def test_invalid_expected_bindings_fail_as_arguments(tmp_path, configuration):
    setup = Setup(tmp_path)
    setup.loaded.registration = configuration
    with pytest.raises(ArgumentError):
        setup.run()
    assert not setup.store.key_path.exists()
    setup.client.register_agent.assert_not_called()


@pytest.mark.parametrize("name", ["", "   ", "x" * 256, "\ud800"])
def test_invalid_names_fail_before_discovery_or_mutation(tmp_path, name):
    setup = Setup(tmp_path)
    with pytest.raises(ArgumentError):
        setup.run(name=name)
    setup.client.get_organization_onboarding.assert_not_called()
    setup.client.register_agent.assert_not_called()
    assert not setup.store.key_path.exists()


def test_name_normalization_and_derived_key_vector(tmp_path):
    from dnsid.managed_registration import _digest, _replay_keys

    fields = [
        "dnsid-managed-registration-v1",
        ORG,
        NAME,
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
    ]
    key = _digest(fields)
    assert key == "2sWNUpI4tnAzJ3quPrT78uJNVdo96m4En3cZsggktcA"
    assert (
        _digest(["dnsid-managed-issuance-v1", key]) == "pxQMSC0k-V9nn9qLqMRDczyUxyNyQE87LbGuK5SEWGw"
    )
    assert _digest(fields[:2] + ["Billing-agent", fields[3]]) != key
    setup = Setup(tmp_path)
    setup.run(name=f" {NAME} ", input=AgentRegistrationInput(name=f" {NAME} ")).manager.close()
    original = _replay_keys(setup.saved())
    assert setup.saved()["name"] == NAME
    assert setup.saved()["input"] is None
    assert setup.saved()["issuance"] is None
    assert set(setup.saved()["acceptance"]) == {"entry_hash", "log_ref"}
    setup.run().manager.close()
    assert _replay_keys(setup.saved()) == original
    with pytest.raises(ArgumentError, match="input.name"):
        setup.run(input=AgentRegistrationInput(name="other"))


def onboarding():
    return {
        "org_id": ORG,
        "governance_domain": GI,
        "gi": {"domain": GI, "state": "verified", "gate_authorized": True},
        "ek": {"status": "verified"},
    }


@pytest.mark.parametrize("missing", ["organization", "gi", "both"])
def test_verified_account_discovery_precedes_generation_and_saved_gi_resumes(tmp_path, missing):
    setup = Setup(tmp_path)
    if missing in {"organization", "both"}:
        setup.loaded.registration.organization_id = ""
    if missing in {"gi", "both"}:
        setup.loaded.registration.governance_id = ""

    def discover():
        assert not setup.store.key_path.exists()
        setup.client.register_agent.assert_not_called()
        return onboarding()

    setup.client.get_organization_onboarding.side_effect = discover
    setup.run().manager.close()
    assert setup.saved()["organization"] == ORG
    assert setup.saved()["governance_id"] == GI
    assert setup.client.get_organization_onboarding.call_count == 1
    setup.loaded.registration.organization_id = ORG
    setup.client.get_organization_onboarding.side_effect = AssertionError("unneeded discovery")
    setup.run().manager.close()


@pytest.mark.parametrize(
    "failure", ["organization", "gi", "proof", "gate", "delegation", "unavailable"]
)
def test_discovery_conflicts_and_unverified_accounts_never_generate(tmp_path, failure):
    setup = Setup(tmp_path)
    raw = onboarding()
    if failure == "organization":
        setup.loaded.registration.governance_id = ""
        raw["org_id"] = "another-account"
    else:
        setup.loaded.registration.organization_id = ""
    if failure == "gi":
        raw["governance_domain"] = raw["gi"]["domain"] = "other.test"
    elif failure == "proof":
        raw["gi"]["state"] = "pending"
    elif failure == "gate":
        raw["gi"]["gate_authorized"] = False
    elif failure == "delegation":
        raw["ek"]["status"] = "pending"
    if failure == "unavailable":
        setup.client.get_organization_onboarding.side_effect = RegistryRequestError(
            "/org", 403, "FORBIDDEN"
        )
    else:
        setup.client.get_organization_onboarding.return_value = raw
    with pytest.raises(ManagedRegistrationError):
        setup.run()
    setup.client.register_agent.assert_not_called()
    assert not setup.store.key_path.exists()


def test_named_storage_isolates_tenants_names_registries_and_private_keys(tmp_path):
    root = FileRegistrationStore(tmp_path / "state")
    selected = [
        root.select(*scope)
        for scope in (
            ("https://registry.test", ORG, "../billing"),
            ("https://registry.test", "other-account", "../billing"),
            ("https://other.test", ORG, "../billing"),
            ("https://registry.test", ORG, "Billing"),
        )
    ]
    assert len({store.directory for store in selected}) == 4
    assert len({store.key_path for store in selected}) == 4
    for store in selected:
        assert store.directory.is_relative_to(root.directory)
        assert store.key_path.is_relative_to(root.directory / "keys")
        assert not store.key_path.is_relative_to(store.directory)
    first = selected[0]
    second = root.select("https://registry.test", ORG, "../billing")
    with first.exclusive():
        with pytest.raises(ManagedRegistrationError, match="busy"):
            with second.exclusive():
                pass
        with selected[1].exclusive():
            selected[1].save({"tenant": "other"})
    assert first.key_path.parent.stat().st_mode & 0o777 == 0o700


def test_new_replica_opens_included_issuance_without_preparation(tmp_path, monkeypatch):
    from dnsid.managed_registration import _replay_keys

    setup = Setup(tmp_path)
    setup.run().manager.close()
    keys = _replay_keys(setup.saved())
    replica = FileRegistrationStore(tmp_path / "replica")
    monkeypatch.setattr(
        "dnsid.managed_registration.RegistryClient", Mock(return_value=setup.client)
    )
    result = register_managed_identity(
        NAME,
        setup.loaded,
        "replacement-credential",
        replica,
        key_provider=setup.operational,
        provider_reference="shared-existing-key",
        deps=setup.deps,
        log_registry_reference="test-trust-v1",
        interval=0.001,
    )
    result.manager.close()
    replica = replica.select("https://registry.test", ORG, NAME)
    with replica.exclusive():
        state = replica.load()
    assert _replay_keys(state) == keys
    assert state["complete"] and state["issuance"] is None
    assert setup.client.register_agent.call_count == 2
    assert setup.client.prepare_issuance.call_count == 1
    assert setup.client.submit_prepared_event.call_count == 1


def test_failed_historical_retrieval_never_reissues(tmp_path):
    setup = Setup(tmp_path)
    setup.run().manager.close()
    original = setup.saved()
    setup.reader.recover_issuance.side_effect = VerificationError(
        VerificationCode.LOG_ERROR, "unavailable"
    )
    with pytest.raises(ManagedRegistrationError):
        setup.run()
    assert setup.saved() == original
    assert setup.client.prepare_issuance.call_count == 1
    assert setup.client.submit_prepared_event.call_count == 1


def test_completed_rotation_follows_signed_new_ku_and_retains_creation_snapshot(tmp_path):
    setup = Setup(tmp_path)
    setup.run().manager.close()
    original = setup.saved()["registration"]
    initial = setup.operational.signing_key()
    kid = setup.operational.generate_key()
    setup.operational.activate(kid)
    setup.operational.supersede(initial.kid)
    current = setup.operational.signing_key()
    setup.history.append(
        KeyRotationEvent(
            domain=DOMAIN,
            timestamp=NOW + datetime.timedelta(seconds=1),
            previous_thumbprint=initial.thumbprint(),
            new_thumbprint=current.thumbprint(),
            new_public_key=current,
        )
    )
    setup.publication.ku_url = f"https://{DOMAIN}/.well-known/{current.thumbprint()}-jwks.json"
    setup.publish()
    result = setup.run()
    assert result.manager._config.identity.ku_url == setup.publication.ku_url
    assert setup.saved()["registration"] == original
    result.manager.close()
    assert setup.client.prepare_issuance.call_count == 1


@pytest.mark.parametrize("provider", ["aws-kms", "google-kms", "azure-key-vault"])
def test_unavailable_provider_stops_before_account_discovery_or_mutation(
    tmp_path, monkeypatch, provider
):
    import importlib

    from dnsid import KeySource

    setup = Setup(tmp_path)
    setup.loaded.registration.organization_id = ""
    setup.loaded.key_source = KeySource(provider=provider, key_ref="existing")
    monkeypatch.setattr(importlib, "import_module", Mock(side_effect=ImportError()))
    with pytest.raises(ArgumentError, match=f"{provider} unavailable; install"):
        setup.run()
    setup.client.get_organization_onboarding.assert_not_called()
    setup.client.register_agent.assert_not_called()
    assert not setup.store.key_path.exists()


def test_injected_provider_ignores_displaced_unavailable_selection_and_entity_file(tmp_path):
    from dnsid import KeySource

    setup = Setup(tmp_path)
    setup.operational = LocalKeyProvider.generate()
    setup.loaded.key_source = KeySource(
        provider="google-kms", entity_key_path="/missing/entity-private-key"
    )
    setup.run(key_provider=setup.operational, provider_reference="explicit-key").manager.close()
    assert not setup.store.key_path.exists()


def test_explicit_file_generation_is_scoped_and_recoverable(tmp_path):
    from dnsid import KeyGenerationConfig, KeySource

    setup = Setup(tmp_path)
    setup.loaded.key_source = KeySource(
        provider="file",
        generation=KeyGenerationConfig(str(tmp_path / "private"), "ES256"),
    )
    with pytest.warns(UserWarning, match="unsuitable for production"):
        setup.run().manager.close()
    assert setup.operational.signing_key().alg == "ES256"
    locator = Path(setup.saved()["key_locator"])
    assert locator.is_relative_to(tmp_path / "private")
    assert not locator.is_relative_to(setup.store.directory)
    setup.run().manager.close()
    assert setup.client.register_agent.call_count == 1


def test_explicit_terminal_replacement_retains_history_and_rejects_previous_keys(tmp_path):
    from dnsid.models import RetirementEvent

    setup = Setup(tmp_path)
    setup.run().manager.close()
    initial = setup.operational.signing_key()
    setup.registration.registry_status = "RETIRED"
    setup.history.append(
        RetirementEvent(domain=DOMAIN, timestamp=NOW + datetime.timedelta(seconds=1))
    )
    original = setup.saved()
    with pytest.raises(ManagedRegistrationError, match="historical_key_reuse"):
        setup.run(
            replace_terminal=True, key_provider=setup.operational, provider_reference="old-key"
        )
    assert setup.saved() == original
    assert setup.saved()["initial_key"] == initial.to_dict()
    assert setup.client.register_agent.call_count == 1


def test_replacement_requires_confirmed_terminal_history(tmp_path):
    setup = Setup(tmp_path)
    setup.run().manager.close()
    original = setup.saved()
    with pytest.raises(ManagedRegistrationError, match="replacement_requires_terminal"):
        setup.run(replace_terminal=True)
    assert setup.saved() == original
    assert setup.client.register_agent.call_count == 1


def test_fresh_key_replacement_has_new_identity_and_keeps_old_operation(tmp_path, monkeypatch):
    import sys
    from dataclasses import replace

    from dnsid.managed_registration import _replay_keys
    from dnsid.models import RetirementEvent

    setup = Setup(tmp_path)
    setup.run().manager.close()
    old = setup.saved()
    old_key = _replay_keys(old)[0]
    old_provider = setup.operational
    setup.registration.registry_status = "RETIRED"
    setup.history.append(
        RetirementEvent(domain=DOMAIN, timestamp=NOW + datetime.timedelta(seconds=1))
    )
    register = setup.register

    def replacement(request, key):
        assert key != old_key
        state = setup.saved()
        assert state["history"][0]["registration"] == old["registration"]
        assert state["key_locator"] != old["key_locator"]
        monkeypatch.setattr(sys.modules[__name__], "DOMAIN", "replacement.other.test")
        monkeypatch.setattr(
            sys.modules[__name__], "LR", "c2sp-tlog:public:https://log.test#instance-2"
        )
        setup.publication = replace(
            setup.publication,
            ku_url=f"https://{DOMAIN}/ku.json",
            status_url=f"https://{DOMAIN}/status",
            log_ref=LR,
        )
        setup.registration = replace(
            setup.registration,
            id="immutable-2",
            domain=DOMAIN,
            registry_status="VERIFIED",
            dns_published=False,
            publication_config=setup.publication,
        )
        setup.operational = None
        setup.client.get_registration.return_value = setup.registration
        setup.status = RegistryAgentStatus("VERIFIED", False, None, True, False, False, False)
        setup.client.get_agent_status.return_value = setup.status
        setup.client.wait_for_status.return_value = setup.status
        setup.history = []
        setup.entry = None
        return register(request, key)

    setup.client.register_agent.side_effect = replacement
    result = setup.run(replace_terminal=True)
    assert result.registration.id == "immutable-2"
    assert setup.saved()["history"][0]["registration"]["id"] == "immutable-1"
    assert setup.saved()["initial_key"] != old_provider.signing_key().to_dict()
    result.manager.close()
    setup.run().manager.close()
    assert setup.client.register_agent.call_count == 2
    assert setup.client.submit_prepared_event.call_count == 2


def test_completed_open_can_observe_authorized_provider_transition(tmp_path):
    setup = Setup(tmp_path)
    setup.run().manager.close()
    initial = setup.operational.signing_key()
    with pytest.raises(ManagedRegistrationError, match="provider_rotation_required"):
        setup.run(key_provider=setup.operational, provider_reference="new-provider")
    kid = setup.operational.generate_key()
    setup.operational.activate(kid)
    setup.operational.supersede(initial.kid)
    current = setup.operational.signing_key()
    setup.history.append(
        KeyRotationEvent(
            domain=DOMAIN,
            timestamp=NOW + datetime.timedelta(seconds=1),
            previous_thumbprint=initial.thumbprint(),
            new_thumbprint=current.thumbprint(),
            new_public_key=current,
        )
    )
    setup.publish()
    setup.run(key_provider=setup.operational, provider_reference="new-provider").manager.close()
    assert setup.saved()["provider"] == "new-provider"
    assert setup.saved()["initial_key"] == initial.to_dict()
    assert setup.client.prepare_issuance.call_count == 1
    assert setup.client.submit_prepared_event.call_count == 1


def test_configured_cloud_key_works_for_named_registration(tmp_path, monkeypatch):
    import importlib

    from dnsid import KeySource

    setup = Setup(tmp_path)
    setup.operational = LocalKeyProvider.generate()
    module = SimpleNamespace(
        validate_config=Mock(), key_provider_from_config=Mock(return_value=setup.operational)
    )
    load = Mock(return_value=module)
    monkeypatch.setattr(importlib, "import_module", load)
    setup.loaded.key_source = KeySource(provider="google-kms", key_ref="stable-version")
    setup.run().manager.close()
    assert all(call.args == ("dnsid_google_kms",) for call in load.call_args_list)
    module.key_provider_from_config.assert_called_once()


@pytest.mark.parametrize(
    "spec",
    [
        {"locator": 42, "algorithm": "EdDSA"},
        {"locator": "stable", "algorithm": "EdDSA", "nonce": "no"},
    ],
)
def test_generation_file_shape_is_strict(tmp_path, spec):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"keySource": {"generation": spec}}))
    with pytest.raises(ArgumentError):
        load_file(path)


def test_named_state_scope_tampering_and_legacy_root_are_not_mutated(tmp_path):
    setup = Setup(tmp_path)
    interrupt_creation(setup)
    state = setup.saved()
    state["organization"] = "another-account"
    with setup.store.exclusive():
        setup.store.save(state)
    with pytest.raises(ManagedRegistrationError, match="account_binding"):
        setup.run()
    assert setup.saved() == state
    assert setup.client.register_agent.call_count == 1
    root = tmp_path / "legacy"
    root.mkdir()
    artifact = root / "registration.json"
    artifact.write_text('{"version": 2}')
    named = FileRegistrationStore(root).select("https://registry.test", ORG, NAME)
    with pytest.raises(ManagedRegistrationError, match="legacy_store"):
        with named.exclusive():
            pass
    assert artifact.read_text() == '{"version": 2}'


def test_known_identity_read_failure_never_replays_creation(tmp_path):
    setup = Setup(tmp_path)
    setup.run().manager.close()
    original = setup.saved()
    setup.client.get_agent_detail.side_effect = RegistryRequestError("/detail", 403, "FORBIDDEN")
    with pytest.raises(ManagedRegistrationError) as error:
        setup.run()
    assert error.value.status_code == 403
    assert setup.saved() == original
    assert setup.client.register_agent.call_count == 1


def test_onboarding_uses_authenticated_effective_transport_and_registry_categories(monkeypatch):
    import httpx

    from dnsid import TransportConfig, verification_budget

    client = RegistryClient(
        "https://registry.test",
        api_key="owner-token",
        transport_config=TransportConfig(private_address_hosts=frozenset({"registry.test"})),
    )
    seen = []

    def request(method, url, **kwargs):
        seen.append((method, url, kwargs))
        return httpx.Response(200, json=onboarding())

    monkeypatch.setattr(client, "_http_request", request)
    with verification_budget(1):
        assert client.get_organization_onboarding() == onboarding()
    assert seen[0][0:2] == ("GET", "https://registry.test/api/v1/org/onboarding")
    assert seen[0][2]["headers"] == {"Authorization": "Bearer owner-token"}
    monkeypatch.setattr(
        client,
        "_http_request",
        lambda *args, **kwargs: httpx.Response(
            403,
            json={"error": "FORBIDDEN", "credential": "owner-token"},
        ),
    )
    with pytest.raises(RegistryRequestError) as denied:
        client.get_organization_onboarding()
    assert denied.value.status_code == 403 and denied.value.error_code == "FORBIDDEN"
    assert "owner-token" not in str(denied.value)
