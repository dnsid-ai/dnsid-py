"""Managed setup persists exact bytes, resumes, and rejects changed bindings."""

import datetime
import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from dnsid import LocalKeyProvider, ManagedIssuanceState, issue_managed_identity
from dnsid.c2sp_tlog import C2spSignerRole, prepare_event, sign_prepared_event
from dnsid.exceptions import ArgumentError, VerificationError
from dnsid.models import IssuanceEvent, LogRef, SubmissionResult

DOMAIN = "agent.sandbox.dev.dnsid.ai"
LR = "c2sp-tlog:public:https://log.dev.dnsid.ai#agent-123"


def setup_operation():
    entity, operational = LocalKeyProvider.generate(), LocalKeyProvider.generate()
    prepared = sign_prepared_event(
        prepare_event(
            IssuanceEvent(
                domain=DOMAIN,
                governance_id="dev.dnsid.ai",
                timestamp=datetime.datetime(2026, 7, 1, tzinfo=datetime.UTC),
                entity_key=entity.signing_key(),
                operational_key=operational.signing_key(),
            ),
            LR,
        ),
        C2spSignerRole.ENTITY,
        entity,
    )
    from dnsid.c2sp_tlog import canonical_bytes

    registry = Mock()
    registry.prepare_issuance.return_value = SimpleNamespace(
        entry_bytes=canonical_bytes(prepared.envelope),
        log_reference=LR,
    )
    options = dict(
        domain=DOMAIN,
        governance_id="dev.dnsid.ai",
        log_reference=LR,
        entity_key=entity.signing_key(),
        operational_key_provider=operational,
        registry_client=registry,
        idempotency_key="issuance-1",
    )
    return options, registry


def accepted(entry):
    return SubmissionResult(
        "accepted", hashlib.sha256(entry).hexdigest(), 3, LogRef.parse(f"{LR}@3")
    )


def test_issue_resumes_exact_bytes_and_does_not_resubmit_accepted_or_rejected():
    options, registry = setup_operation()
    snapshots = []

    def persist(state):
        snapshots.append(ManagedIssuanceState.from_dict(json.loads(json.dumps(state.to_dict()))))

    def prepare(*args):
        assert snapshots and not snapshots[-1].entry  # Intent precedes remote mutation.
        return registry.prepare_issuance.return_value

    def submit(domain, entry, key):
        assert snapshots[-1].entry == entry and key == snapshots[-1].idempotency_key
        return SubmissionResult("pending")

    registry.prepare_issuance.side_effect = prepare
    registry.submit_prepared_event.side_effect = submit
    state = issue_managed_identity(**options, persist_issuance=persist)
    original = state.entry
    assert state.submission.state == "pending"
    registry.submit_prepared_event.side_effect = lambda domain, entry, key: accepted(entry)
    state = issue_managed_identity(**options, persist_issuance=persist, issuance=state)
    assert state.entry == original and state.submission.accepted
    issue_managed_identity(**options, persist_issuance=persist, issuance=state)
    assert registry.prepare_issuance.call_count == 1
    assert registry.submit_prepared_event.call_count == 2
    for call in registry.submit_prepared_event.call_args_list:
        assert call.args == (DOMAIN, original, "issuance-1")
    with pytest.raises(VerificationError, match="rejected"):
        issue_managed_identity(
            **options,
            persist_issuance=persist,
            issuance=replace(state, submission=SubmissionResult("rejected")),
        )
    assert registry.submit_prepared_event.call_count == 2
    with pytest.raises(VerificationError, match="no exact bytes"):
        issue_managed_identity(
            **options, persist_issuance=persist, issuance=replace(state, entry=b"")
        )
    assert registry.prepare_issuance.call_count == 1
    with pytest.raises(ArgumentError, match="another operation"):
        issue_managed_identity(
            **{**options, "domain": "other.sandbox.dev.dnsid.ai"},
            persist_issuance=persist,
            issuance=state,
        )


def test_issue_persistence_failure_prevents_submission_and_bad_acceptance_fails():
    options, registry = setup_operation()

    def fail_after_intent(state):
        if state.entry:
            raise OSError("disk full")

    with pytest.raises(OSError, match="disk full"):
        issue_managed_identity(**options, persist_issuance=fail_after_intent)
    registry.submit_prepared_event.assert_not_called()
    snapshots = []
    registry.submit_prepared_event.return_value = SubmissionResult(
        "accepted", "wrong hash", 3, LogRef.parse(f"{LR}@3")
    )
    with pytest.raises(VerificationError, match="mismatch"):
        issue_managed_identity(**options, persist_issuance=snapshots.append)
    with pytest.raises(VerificationError, match="mismatch"):
        issue_managed_identity(**options, persist_issuance=snapshots.append, issuance=snapshots[-1])
    assert registry.submit_prepared_event.call_count == 1


def test_issue_wrong_preparation_is_terminal():
    options, registry = setup_operation()
    registry.prepare_issuance.return_value.log_reference = LR + "other"
    snapshots = []
    with pytest.raises(VerificationError, match="reference"):
        issue_managed_identity(**options, persist_issuance=snapshots.append)
    assert snapshots[-1].terminal_failure
    with pytest.raises(VerificationError, match="rejected"):
        issue_managed_identity(**options, persist_issuance=snapshots.append, issuance=snapshots[-1])
    assert registry.prepare_issuance.call_count == 1
    registry.submit_prepared_event.assert_not_called()


@pytest.mark.parametrize(
    "field,value",
    [
        ("fqdn", "other.sandbox.dev.dnsid.ai"),
        ("gi", "other.dnsid.ai"),
        ("sigs", {}),
    ],
)
def test_issue_rejects_untrusted_preparation_before_submission(field, value):
    from dnsid.c2sp_tlog import C2spTlogError, canonical_bytes

    options, registry = setup_operation()
    raw = registry.prepare_issuance.return_value
    envelope = json.loads(raw.entry_bytes)
    envelope[field] = value
    raw.entry_bytes = canonical_bytes(envelope)
    snapshots = []
    with pytest.raises((VerificationError, C2spTlogError)):
        issue_managed_identity(**options, persist_issuance=snapshots.append)
    assert snapshots[-1].terminal_failure
    registry.submit_prepared_event.assert_not_called()
