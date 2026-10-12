"""Regression checks for design 01, 05, 09, 11 and 12 boundaries."""

import copy
import datetime
import hashlib
import importlib
import os
import pickle
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock, patch

import httpx
import pytest

from dnsid import (
    IdentityManager,
    IssuanceOperation,
    KeySource,
    LoadedConfig,
    LocalKeyProvider,
    LogTrust,
    RegistryClient,
    construct_identity_manager,
    resume_issuance,
)
from dnsid._default_resolver import DefaultDNSResolver
from dnsid.c2sp_tlog import (
    C2spSignerRole,
    canonical_bytes,
    prepare_event,
    sign_prepared_event,
)
from dnsid.c2sp_tlog.errors import C2spTlogVerificationError
from dnsid.exceptions import ArgumentError, ValidationError
from dnsid.models import IssuanceEvent, LogRef, PreparedRegistryEvent, SubmissionResult
from dnsid.oidc import _MAX_BODY_BYTES, NetworkError, _post_form_json
from tests._config import make_config
from tests.test_default_dns_resolver import _doh_response
from tests.test_verification_coalescing import _manager_fixture

DOMAIN = "agent.example.com"
GI = "example.com"
LR = "c2sp-tlog:testnet:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"


@pytest.mark.parametrize("status", [200, 400, 503])
def test_token_body_limit_stops_stream_before_parsing(status):
    reads = []

    class Body(httpx.SyncByteStream):
        def __iter__(self):
            for i in range(20):
                reads.append(i)
                yield b"x" * _MAX_BODY_BYTES

    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(status, stream=Body()))
    ) as client:
        with pytest.raises(NetworkError, match="too large"):
            _post_form_json("https://issuer.example/token", {}, http_client=client)
    assert reads == [0, 1]


def test_missing_doh_ttl_succeeds_only_for_acquiring_operation(ec_pair):
    manager, resolver, counts, domain, keys, status, _ = _manager_fixture(ec_pair)
    txt = resolver.records[f"_dnsid.{domain}"].concatenate_strings()
    manager._dns_resolver = DefaultDNSResolver("https://resolver.example")
    response = _doh_response({"Status": 0, "Answer": [{"type": 16, "data": f'"{txt}"'}]})
    with (
        manager,
        patch("httpx.Client.stream", return_value=response) as stream,
        patch("dnsid.manager._fetch_jwks", side_effect=keys),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
    ):
        assert manager.verify_domain(domain).dns_ttl == 0
        assert manager._cache.get(domain) is None
        assert manager.verify_domain(domain).dns_ttl == 0
        assert stream.call_count == 2
        assert counts["ku"] == 2


@pytest.mark.parametrize(
    "source",
    [
        KeySource(provider="google-kms", key_ref="version-1"),
        KeySource(provider="file", settings={"secret": "no"}),
    ],
)
def test_invalid_provider_fails_before_policy_or_discovery(monkeypatch, source):
    loaded = LoadedConfig(
        dnsid=make_config(
            domain=DOMAIN, governance_id=GI, log_ref=LR, status_url=f"https://{DOMAIN}/status"
        ),
        key_source=source,
        log_trust=LogTrust(policy_url="https://policy.example/policy"),
    )
    with (
        patch("dnsid.config_loading._log_registry_from_trust") as policy,
        patch.object(IdentityManager, "_verify_publication_evidence") as discovery,
        pytest.raises(ArgumentError),
    ):
        monkeypatch.setattr(importlib, "import_module", Mock(side_effect=ImportError))
        construct_identity_manager(loaded)
    policy.assert_not_called()
    discovery.assert_not_called()


@pytest.mark.parametrize("mismatch", ["kid", "alg", "key", "gi", "lr", None])
def test_configured_signer_matches_verified_publication(tmp_path, monkeypatch, mismatch):
    path = tmp_path / "key.json"
    provider = LocalKeyProvider.load(path, create_if_missing=True)
    published = copy.deepcopy(provider.signing_key())
    if mismatch == "key":
        published = LocalKeyProvider.generate().signing_key()
    elif mismatch in {"kid", "alg"}:
        setattr(published, mismatch, "changed")
    observed = SimpleNamespace(
        record=SimpleNamespace(
            gi="other.example" if mismatch == "gi" else GI,
            lr="other:log" if mismatch == "lr" else LR,
            v="dnsid-draft-01",
        ),
        jwks=SimpleNamespace(current_operational_signing_key=lambda _: published),
    )
    monkeypatch.setattr(
        IdentityManager, "_verify_publication_evidence", Mock(return_value=observed)
    )
    loaded = LoadedConfig(
        dnsid=make_config(
            domain=DOMAIN, governance_id=GI, log_ref=LR, status_url=f"https://{DOMAIN}/status"
        ),
        key_source=KeySource(key_ref=str(path)),
    )
    with patch.object(IdentityManager, "close", autospec=True) as close:
        with pytest.warns(UserWarning):
            if mismatch:
                with pytest.raises(ValidationError, match="publication"):
                    construct_identity_manager(loaded)
                close.assert_called_once()
            else:
                manager = construct_identity_manager(loaded)
                close.assert_not_called()
                manager.close()


def test_configured_entity_signer_must_match_publication(tmp_path, monkeypatch):
    import json

    from tests.test_local_key_provider_cli import _make_private_jwk

    path = tmp_path / "entity.jwk"
    path.write_text(json.dumps(_make_private_jwk()))
    loaded = LoadedConfig(
        dnsid=make_config(
            domain=DOMAIN, governance_id=GI, log_ref=LR, status_url=f"https://{DOMAIN}/status"
        ),
        key_source=KeySource(entity_key_path=str(path)),
    )
    observed = SimpleNamespace(
        record=SimpleNamespace(gi=GI, lr=LR),
        signing_key=LocalKeyProvider.generate().signing_key(),
    )
    monkeypatch.setattr(
        IdentityManager, "_verify_publication_evidence", Mock(return_value=observed)
    )
    with pytest.raises(ValidationError, match="signer"):
        construct_identity_manager(loaded, key_provider=LocalKeyProvider.generate())


@pytest.mark.parametrize(
    "change,ready",
    [
        ({}, True),
        ({"gi": None}, False),
        ({"ek": None}, False),
        ({"ek": {"status": "pending"}}, False),
        ({"gi": {"domain": GI, "state": "pending", "gate_authorized": True}}, False),
        ({"gi": {"domain": GI, "state": "verified", "gate_authorized": "true"}}, False),
    ],
)
def test_onboarding_readiness_preserves_pending(monkeypatch, change, ready):
    body = {
        "org_id": "org-1",
        "governance_domain": GI,
        "gi": {"domain": GI, "state": "verified", "gate_authorized": True},
        "ek": {"status": "verified"},
        "bindings_ready": True,
        **change,
    }
    with RegistryClient("https://registry.example", api_key="owner") as client:
        monkeypatch.setattr(
            client, "_http_request", lambda *a, **kw: httpx.Response(200, json=body)
        )
        result = client.get_organization_onboarding(expected_org_id="org-1", expected_gi=GI)
    assert result == {**body, "bindings_ready": ready}


@pytest.mark.parametrize(
    "change",
    [
        {"org_id": ""},
        {"org_id": "org-2"},
        {"governance_domain": "other.example"},
        {"governance_domain": "https://example.com"},
        {"governance_domain": 123},
        {"gi": {"domain": "other.example", "state": "verified", "gate_authorized": True}},
    ],
)
def test_onboarding_rejects_binding_mismatch(monkeypatch, change):
    body = {"org_id": "org-1", "governance_domain": GI, **change}
    with RegistryClient("https://registry.example", api_key="owner") as client:
        monkeypatch.setattr(
            client, "_http_request", lambda *a, **kw: httpx.Response(200, json=body)
        )
        with pytest.raises((ArgumentError, ValidationError)):
            client.get_organization_onboarding(expected_org_id="org-1", expected_gi=GI)


@pytest.fixture
def issuance(tmp_path):
    entity, operational = LocalKeyProvider.generate(), LocalKeyProvider.generate()
    event = IssuanceEvent(
        domain=DOMAIN,
        governance_id=GI,
        timestamp=datetime.datetime.now(datetime.UTC).replace(microsecond=0),
        entity_key=entity.signing_key(),
        operational_key=operational.signing_key(),
    )
    prepared = sign_prepared_event(prepare_event(event, LR), C2spSignerRole.ENTITY, entity)
    registry = Mock(spec=RegistryClient)
    registry.prepare_issuance.return_value = PreparedRegistryEvent(
        canonical_bytes(prepared.envelope), LR
    )
    operation = IssuanceOperation(
        DOMAIN, GI, LR, entity.signing_key(), operational.signing_key(), "issuance-1"
    )
    path = tmp_path / "issuance.pickle"

    def persist(state):
        # Test storage, not a production serialization format.
        with path.open("wb") as file:
            pickle.dump(state, file)
            file.flush()
            os.fsync(file.fileno())

    def load():
        return pickle.loads(path.read_bytes())

    registry.submit_prepared_event.side_effect = lambda domain, data, key: SubmissionResult(
        "accepted",
        entry_hash=hashlib.sha256(data).hexdigest(),
        index=7,
        log_ref=LogRef.parse(f"{LR}@7"),
    )
    hooks = {"persist": persist, "verify_publication": Mock(), "activate": Mock()}
    return operation, registry, operational, hooks, load


def test_issuance_restart_retries_exact_bytes_and_activation(issuance):
    operation, registry, provider, hooks, load = issuance
    registry.submit_prepared_event.side_effect = RuntimeError("timeout after append")
    with pytest.raises(RuntimeError):
        resume_issuance(operation, registry, provider, **hooks)
    saved = load()
    assert saved.entry_bytes and saved.submission is None
    original = registry.submit_prepared_event.call_args
    registry.submit_prepared_event.side_effect = lambda *args: SubmissionResult(
        "accepted", saved.entry_hash, 7, LogRef.parse(f"{LR}@7")
    )
    hooks["activate"].side_effect = RuntimeError("publication unavailable")
    with pytest.raises(RuntimeError):
        resume_issuance(saved, registry, provider, **hooks)
    assert registry.submit_prepared_event.call_args == original
    assert load().submission.accepted
    hooks["activate"].side_effect = None
    completed = resume_issuance(load(), registry, provider, **hooks)
    assert completed.completed and load().completed
    assert resume_issuance(load(), registry, provider, **hooks) == completed
    assert registry.prepare_issuance.call_count == 1
    assert registry.submit_prepared_event.call_count == 2
    assert hooks["activate"].call_count == 2


@pytest.mark.parametrize("bad", ["hash", "reference", "index", "missing-reference"])
def test_issuance_acceptance_must_bind_exact_entry(issuance, bad):
    operation, registry, provider, hooks, load = issuance

    def submit(domain, data, key):
        return SubmissionResult(
            "accepted",
            "wrong" if bad == "hash" else hashlib.sha256(data).hexdigest(),
            index=8 if bad == "index" else 7,
            log_ref=None
            if bad == "missing-reference"
            else LogRef.parse(
                f"{LR}@7"
                if bad != "reference"
                else "c2sp-tlog:testnet:https://other.example#instance@7"
            ),
        )

    registry.submit_prepared_event.side_effect = submit
    with pytest.raises(ValidationError):
        resume_issuance(operation, registry, provider, **hooks)
    assert load().entry_bytes
    hooks["activate"].assert_not_called()


@pytest.mark.parametrize("state", ["pending", "rejected"])
def test_issuance_pending_and_rejected_never_activate(issuance, state):
    operation, registry, provider, hooks, load = issuance
    registry.submit_prepared_event.side_effect = None
    registry.submit_prepared_event.return_value = SubmissionResult(state, error_code="BUSY")
    result = resume_issuance(operation, registry, provider, **hooks)
    assert load().submission.error_code == "BUSY"
    resume_issuance(load(), registry, provider, **hooks)
    assert registry.prepare_issuance.call_count == 1
    assert registry.submit_prepared_event.call_count == (2 if state == "pending" else 1)
    hooks["activate"].assert_not_called()
    assert not result.completed


def test_issuance_persistence_failure_blocks_network(issuance):
    operation, registry, provider, hooks, load = issuance
    hooks["persist"] = Mock(side_effect=OSError("disk full"))
    with pytest.raises(OSError):
        resume_issuance(operation, registry, provider, **hooks)
    registry.prepare_issuance.assert_not_called()
    registry.submit_prepared_event.assert_not_called()
    hooks["activate"].assert_not_called()


def test_issuance_rejects_corrupt_saved_bytes(issuance):
    operation, registry, provider, hooks, load = issuance
    registry.submit_prepared_event.side_effect = RuntimeError("interrupted")
    with pytest.raises(RuntimeError):
        resume_issuance(operation, registry, provider, **hooks)
    saved = replace(load(), entry_hash="wrong")
    registry.reset_mock()
    with pytest.raises(ValidationError):
        resume_issuance(saved, registry, provider, **hooks)
    registry.submit_prepared_event.assert_not_called()


@pytest.mark.parametrize("phase", ["signed", "accepted", "completed"])
def test_issuance_crash_at_durable_transition(issuance, phase):
    operation, registry, provider, hooks, load = issuance
    commit = hooks["persist"]
    active = set()
    changes = []

    def persist(state):
        at_phase = {
            "signed": bool(state.entry_bytes) and state.submission is None,
            "accepted": state.submission is not None and not state.completed,
            "completed": state.completed,
        }[phase]
        if at_phase:
            raise OSError("commit failed")
        commit(state)

    def activate(state):
        assert load().submission.accepted
        if state.entry_hash not in active:
            active.add(state.entry_hash)
            changes.append(state.entry_hash)

    original_submit = registry.submit_prepared_event.side_effect

    def submit(domain, data, key):
        assert load().entry_bytes == data
        assert load().idempotency_key == key
        return original_submit(domain, data, key)

    registry.submit_prepared_event.side_effect = submit
    hooks.update(persist=persist, activate=activate)
    with pytest.raises(OSError):
        resume_issuance(operation, registry, provider, **hooks)
    assert len(changes) == (1 if phase == "completed" else 0)
    if phase == "signed":
        registry.submit_prepared_event.assert_not_called()
    hooks["persist"] = commit
    completed = resume_issuance(load(), registry, provider, **hooks)
    assert completed.completed
    assert changes == [completed.entry_hash]
    if phase == "accepted":
        sent = registry.submit_prepared_event.call_args_list
        assert sent[0] == sent[1]
    elif phase == "completed":
        assert registry.submit_prepared_event.call_count == 1


@pytest.mark.parametrize("changed", ["domain", "governance_id", "log_reference", "entity_key"])
def test_issuance_preparation_must_match_intent(issuance, changed):
    operation, registry, provider, hooks, load = issuance
    replacement = {
        "domain": "other.example.com",
        "governance_id": "other.example",
        "log_reference": "c2sp-tlog:testnet:https://other.example#instance",
        "entity_key": LocalKeyProvider.generate().signing_key(),
    }[changed]
    operation = replace(operation, **{changed: replacement})
    with pytest.raises((ValidationError, C2spTlogVerificationError)):
        resume_issuance(operation, registry, provider, **hooks)
    registry.submit_prepared_event.assert_not_called()
    hooks["activate"].assert_not_called()
