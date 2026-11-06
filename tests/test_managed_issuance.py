"""Managed ISSUANCE uses durable intent, trusted countersigning, and exact retries."""

from __future__ import annotations

import copy
import datetime
import hashlib
from dataclasses import replace
from unittest.mock import DEFAULT, Mock

import pytest

from dnsid import LocalKeyProvider, LogRef, PreparedRegistryEvent, SubmissionResult
from dnsid.c2sp_tlog import (
    C2spSignerRole,
    ManagedIssuanceInProgressError,
    ManagedIssuanceOperationError,
    begin_managed_issuance,
    complete_managed_issuance,
    prepare_event,
    resume_managed_issuance,
    sign_prepared_event,
)
from dnsid.c2sp_tlog.canonical import canonical_bytes
from dnsid.exceptions import ArgumentError, RegistryRequestError, ValidationError
from dnsid.models import IssuanceEvent

DOMAIN = "agent.example.com"
GI = "example.com"
LR = "c2sp-tlog:testnet:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"


class IssuanceStore:
    def __init__(self):
        self.state = None
        self.writes = []
        self.fail = False

    def create_managed_issuance(self, initial):
        if self.state is not None:
            return copy.deepcopy(self.state)
        self.persist_managed_issuance(initial)
        return None

    def load_managed_issuance(self, domain):
        return copy.deepcopy(self.state)

    def persist_managed_issuance(self, state):
        if self.fail:
            raise OSError("disk unavailable")
        self.state = copy.deepcopy(state)
        self.writes.append(copy.deepcopy(state))


class IssuanceRegistry:
    def __init__(self, entity, operational, store):
        self.entity = entity
        self.operational = operational
        self.store = store
        self.prepares = []
        self.submits = []
        self.error = None
        self.result = None
        self.change = lambda value: value

    def prepare_issuance(self, domain, key):
        assert self.store.state.idempotency_key == key
        self.prepares.append((domain, key))
        event = IssuanceEvent(
            domain=domain, governance_id=GI, entity_key=self.entity.signing_key(),
            operational_key=self.operational.signing_key(),
            timestamp=datetime.datetime(2026, 11, 1, tzinfo=datetime.UTC),
        )
        prepared = prepare_event(event, LR)
        prepared = sign_prepared_event(prepared, C2spSignerRole.ENTITY, self.entity)
        return PreparedRegistryEvent(self.change(canonical_bytes(prepared.envelope)))

    def submit_prepared_event(self, domain, data, key):
        assert self.store.state.entry_bytes == data
        assert self.store.state.submission.state == "pending"
        self.submits.append((domain, data, key))
        if self.error:
            raise self.error
        return self.result or SubmissionResult(
            "accepted", hashlib.sha256(data).hexdigest(), 0, LogRef.parse(f"{LR}@0"),
        )


@pytest.fixture
def setup():
    entity, operational = LocalKeyProvider.generate(), LocalKeyProvider.generate()
    store = IssuanceStore()
    registry = IssuanceRegistry(entity, operational, store)
    block = Mock()
    shared = dict(
        domain=DOMAIN, log_reference=LR, entity_public_key=entity.signing_key(),
        key_provider=operational, registry_client=registry, store=store,
        set_activation_blocked=block,
    )
    return shared, store, registry, block


def begin(shared):
    return begin_managed_issuance(**shared, governance_id=GI, idempotency_key="issuance-1")


def test_acceptance_requires_explicit_public_convergence(setup):
    shared, store, registry, block = setup
    state = begin(shared)
    assert state.submission.accepted
    assert not state.complete and state.activation_blocked
    block.assert_called_once_with(True)
    assert len(registry.prepares) == len(registry.submits) == 1
    completed = complete_managed_issuance(DOMAIN, store, block)
    assert completed.complete and not completed.activation_blocked
    block.assert_called_with(False)
    assert store.writes[-2].complete and store.writes[-2].activation_blocked
    with pytest.raises(ManagedIssuanceInProgressError):
        begin(shared)


def test_lost_response_retries_identical_bytes_and_key(setup):
    shared, store, registry, block = setup
    registry.error = TimeoutError()
    with pytest.raises(ManagedIssuanceOperationError) as caught:
        begin(shared)
    assert caught.value.retry_same_bytes and caught.value.transient
    registry.error = None
    recovered = resume_managed_issuance(**shared)
    assert recovered.submission.accepted
    assert len(registry.prepares) == 1
    assert registry.submits[0] == registry.submits[1]
    assert not recovered.complete


def test_preparation_retry_keeps_durable_intent(setup):
    shared, store, registry, _ = setup
    prepare = registry.prepare_issuance
    registry.prepare_issuance = Mock(side_effect=RegistryRequestError("/prepare", 503, "BUSY"))
    with pytest.raises(ManagedIssuanceOperationError) as caught:
        begin(shared)
    assert caught.value.transient and not caught.value.retry_same_bytes
    assert not store.state.entry_bytes
    registry.prepare_issuance = prepare
    assert resume_managed_issuance(**shared).submission.accepted


@pytest.mark.parametrize("status", [400, 401, 403, 404, 408, 409, 422, 429])
def test_prepare_request_failure_can_resume(setup, status):
    shared, store, registry, _ = setup
    prepare = registry.prepare_issuance
    registry.prepare_issuance = Mock(
        side_effect=RegistryRequestError("/prepare", status, "UNAVAILABLE"),
    )
    with pytest.raises(ManagedIssuanceOperationError) as caught:
        begin(shared)
    assert caught.value.transient and caught.value.status_code == status
    assert not store.state.terminal_failure and not store.state.entry_bytes
    assert not registry.submits
    registry.prepare_issuance.assert_called_once_with(DOMAIN, "issuance-1")
    registry.prepare_issuance = prepare
    assert resume_managed_issuance(**shared).submission.accepted
    assert registry.submits[0][2] == "issuance-1"


@pytest.mark.parametrize("status", [400, 401, 403, 404, 408, 409, 422, 429])
@pytest.mark.parametrize("response", [False, True])
def test_submit_request_failure_retries_same_bytes(setup, status, response):
    shared, store, registry, _ = setup
    if response:
        registry.result = SubmissionResult("rejected", error_code="UNAVAILABLE", status_code=status)
    else:
        registry.error = RegistryRequestError("/submit", status, "UNAVAILABLE")
        registry.error.retry_same_bytes = False
    with pytest.raises(ManagedIssuanceOperationError) as caught:
        begin(shared)
    assert caught.value.transient and caught.value.retry_same_bytes
    assert caught.value.status_code == status
    assert not store.state.terminal_failure and store.state.submission.state == "pending"
    assert store.state.submission.status_code == status
    original = registry.submits[0]
    registry.result = registry.error = None
    assert resume_managed_issuance(**shared).submission.accepted
    assert registry.submits == [original, original] and len(registry.prepares) == 1


@pytest.mark.parametrize("change", [
    lambda data: data.replace(b'"gi":"example.com"', b'"gi":"evil.example"'),
    lambda data: data + b" ",
    lambda data: data.replace(b'"ae":', b'"invalid":'),
])
def test_untrusted_preparation_never_submitted(setup, change):
    shared, store, registry, _ = setup
    registry.change = change
    with pytest.raises(ManagedIssuanceOperationError):
        begin(shared)
    assert not registry.submits
    assert store.state.terminal_failure


@pytest.mark.parametrize("field,value", [
    ("entry_hash", "0" * 64), ("log_reference", LR + "different"),
    ("domain", "other.example.com"), ("activation_blocked", False),
])
def test_resume_rejects_corrupt_state_before_submission(setup, field, value):
    shared, store, registry, _ = setup
    registry.result = SubmissionResult("pending")
    begin(shared)
    store.state = replace(store.state, **{field: value})
    with pytest.raises((ValidationError, ArgumentError)):
        resume_managed_issuance(**shared)
    assert len(registry.submits) == 1


def test_wrong_receipt_does_not_activate(setup):
    shared, store, registry, block = setup
    registry.result = SubmissionResult("accepted", "wrong", 0, LogRef.parse(f"{LR}@0"))
    with pytest.raises(ManagedIssuanceOperationError):
        begin(shared)
    assert store.state.submission.state == "pending"
    assert block.call_args.args == (True,)
    with pytest.raises(ArgumentError):
        complete_managed_issuance(DOMAIN, store, block)


@pytest.mark.parametrize("error_code", [
    "IDEMPOTENCY_MISMATCH", "TLOG_PREPARATION_MISMATCH", "TLOG_INVALID_ENTRY",
])
@pytest.mark.parametrize("stage", ["prepare", "submit-error", "submit-result"])
def test_rejection_is_not_resubmitted(setup, error_code, stage):
    shared, store, registry, _ = setup
    if stage == "prepare":
        registry.prepare_issuance = Mock(
            side_effect=RegistryRequestError("/prepare", 422, error_code),
        )
    elif stage == "submit-error":
        registry.error = RegistryRequestError("/submit", 422, error_code)
    else:
        registry.result = SubmissionResult("rejected", error_code=error_code, status_code=422)
    with pytest.raises(ManagedIssuanceOperationError) as caught:
        begin(shared)
    assert caught.value.state == "rejected" and not caught.value.transient
    assert store.state.terminal_failure
    with pytest.raises(ManagedIssuanceOperationError):
        resume_managed_issuance(**shared)
    assert len(registry.submits) == (0 if stage == "prepare" else 1)


def test_countersigning_provider_fails_once_then_resume_succeeds(setup):
    shared, store, registry, _ = setup
    provider = shared["key_provider"]
    provider.sign_key = Mock(
        wraps=provider.sign_key,
        side_effect=[OSError("KMS temporarily unavailable"), DEFAULT],
    )
    with pytest.raises(ManagedIssuanceOperationError) as caught:
        begin(shared)
    assert caught.value.transient and caught.value.state == "prepared"
    assert not store.state.terminal_failure and store.state.activation_blocked
    assert store.state.prepared_entry_bytes and not store.state.entry_bytes
    assert not registry.submits
    prepared = store.state.prepared_entry_bytes
    recovered = resume_managed_issuance(**shared)
    assert recovered.submission.accepted and not recovered.terminal_failure
    assert recovered.prepared_entry_bytes == prepared
    assert len(registry.prepares) == len(registry.submits) == 1
    assert provider.sign_key.call_count == 2
    assert provider.sign_key.call_args_list[0] == provider.sign_key.call_args_list[1]


def test_resume_accepted_does_not_need_initial_private_key(setup):
    shared, store, registry, _ = setup
    begin(shared)
    shared["key_provider"] = Mock(signing_key=Mock(side_effect=AssertionError("old private key")))
    assert resume_managed_issuance(**shared).submission.accepted
    assert len(registry.submits) == 1


def test_completion_crash_resumes_without_network(setup):
    shared, store, registry, block = setup
    begin(shared)
    block.side_effect = OSError("activation unavailable")
    with pytest.raises(ManagedIssuanceOperationError):
        complete_managed_issuance(DOMAIN, store, block)
    assert store.state.complete and store.state.activation_blocked
    block.side_effect = None
    assert not resume_managed_issuance(**shared).activation_blocked
    assert len(registry.submits) == 1
    block.reset_mock()
    resume_managed_issuance(**shared)
    block.assert_not_called()


def test_persistence_failure_prevents_first_submission(setup):
    shared, store, registry, _ = setup
    original = store.persist_managed_issuance

    def fail_completed(state):
        if state.entry_bytes:
            raise OSError("disk unavailable")
        original(state)

    store.persist_managed_issuance = fail_completed
    with pytest.raises(ManagedIssuanceOperationError):
        begin(shared)
    assert not registry.submits


def test_required_activation_control(setup):
    shared, _, registry, _ = setup
    shared["set_activation_blocked"] = None
    with pytest.raises(ArgumentError):
        begin(shared)
    assert not registry.prepares
