"""Tests for DomainLog.snapshot_at."""

from __future__ import annotations

import datetime

import pytest

from dnsid import JWK
from dnsid.enums import LifecycleErrorCategory
from dnsid.exceptions import LifecycleVerificationError, VerificationError
from dnsid.models import (
    DomainLog,
    IssuanceEvent,
    KeyRotationEvent,
    MigrationEvent,
    RetirementEvent,
    RevocationEvent,
)
from tests.conftest import make_ec_p256_pair

_ZERO = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
_T1 = datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC)
_T2 = datetime.datetime(2024, 6, 1, tzinfo=datetime.UTC)
_T3 = datetime.datetime(2024, 9, 1, tzinfo=datetime.UTC)
_T4 = datetime.datetime(2024, 12, 1, tzinfo=datetime.UTC)

# Real key pairs used across tests — generated once at module load.
_, _JWK_K1 = make_ec_p256_pair("k1")
_, _JWK_K2 = make_ec_p256_pair("k2")
_, _JWK_ENTITY = make_ec_p256_pair("entity")


def _issuance(jwk: JWK, t: datetime.datetime) -> IssuanceEvent:
    return IssuanceEvent(
        domain="agent.example.com",
        governance_id="example.com",
        entity_key=_JWK_ENTITY,
        operational_key=jwk,
        timestamp=t,
    )


def _rotation(prev_jwk: JWK, new_jwk: JWK, t: datetime.datetime) -> KeyRotationEvent:
    return KeyRotationEvent(
        domain="agent.example.com",
        previous_kid=prev_jwk.kid,
        previous_thumbprint=prev_jwk.thumbprint(),
        previous_public_key=prev_jwk,
        new_kid=new_jwk.kid,
        new_thumbprint=new_jwk.thumbprint(),
        new_public_key=new_jwk,
        timestamp=t,
    )


class TestSnapshotAtLifecycleValidation:
    """Design doc 06 §DomainLog: verified-prefix and lifecycle ordering rules."""

    def test_non_prefix_boundary_rejected(self):
        """A future-timestamped event followed by an earlier event at or before
        *at* is not a verified lifecycle prefix."""
        log = DomainLog(
            domain="agent.example.com",
            events=[
                _issuance(_JWK_K1, _T1),
                _rotation(_JWK_K1, _JWK_K2, _T4),  # after the snapshot boundary
                RetirementEvent(domain="agent.example.com", timestamp=_T2),
            ],
        )
        with pytest.raises(VerificationError, match="not a verified lifecycle prefix"):
            log.snapshot_at(_T3)

    def test_wrong_domain_event_rejected(self):
        event = _issuance(_JWK_K1, _T1)
        event.domain = "other.example.com"
        with pytest.raises(LifecycleVerificationError) as exc_info:
            DomainLog("agent.example.com", [event]).snapshot_at(_T2)
        assert exc_info.value.category == LifecycleErrorCategory.DOMAIN_MISMATCH

    @pytest.mark.parametrize(
        "rotation",
        [
            _rotation(_JWK_K2, _JWK_K1, _T2),
            _rotation(_JWK_K1, _JWK_K1, _T2),
        ],
        ids=["stale-previous-key", "same-new-key"],
    )
    def test_rotation_requires_active_key_continuity(self, rotation):
        log = DomainLog("agent.example.com", [_issuance(_JWK_K1, _T1), rotation])
        with pytest.raises(LifecycleVerificationError) as exc_info:
            log.snapshot_at(_T3)
        assert exc_info.value.category == LifecycleErrorCategory.KEY_CONTINUITY

    def test_events_past_boundary_are_skipped_at_the_tail(self):
        """Trailing future events are fine — the prefix simply ends earlier."""
        log = DomainLog(
            domain="agent.example.com",
            events=[
                _issuance(_JWK_K1, _T1),
                _rotation(_JWK_K1, _JWK_K2, _T3),
            ],
        )
        snap = log.snapshot_at(_T2)
        assert snap.historical_state == "ACTIVE"
        assert snap.active_key_thumbprint == _JWK_K1.thumbprint()
        assert len(snap.events) == 1

    def test_reissuance_after_termination_requires_fresh_history(self):
        log = DomainLog(
            domain="agent.example.com",
            events=[
                _issuance(_JWK_K1, _T1),
                RetirementEvent(domain="agent.example.com", timestamp=_T2),
                _issuance(_JWK_K2, _T3),
            ],
        )
        with pytest.raises(LifecycleVerificationError) as exc_info:
            log.snapshot_at(_T4)
        assert exc_info.value.category == LifecycleErrorCategory.TERMINAL_STATE
        assert exc_info.value.failing_event_index == 2

    def test_reissuance_of_unterminated_issuance_rejected(self):
        log = DomainLog(
            domain="agent.example.com",
            events=[
                _issuance(_JWK_K1, _T1),
                _issuance(_JWK_K2, _T2),
            ],
        )
        with pytest.raises(LifecycleVerificationError) as exc_info:
            log.snapshot_at(_T3)
        assert exc_info.value.category == LifecycleErrorCategory.DUPLICATE_ISSUANCE

    def test_rotation_before_issuance_rejected(self):
        log = DomainLog(
            domain="agent.example.com",
            events=[_rotation(_JWK_K1, _JWK_K2, _T1)],
        )
        with pytest.raises(LifecycleVerificationError) as exc_info:
            log.snapshot_at(_T2)
        assert exc_info.value.category == LifecycleErrorCategory.GENESIS_REQUIRED

    def test_rotation_after_termination_rejected(self):
        log = DomainLog(
            domain="agent.example.com",
            events=[
                _issuance(_JWK_K1, _T1),
                RevocationEvent(domain="agent.example.com", reason="keyCompromise", timestamp=_T2),
                _rotation(_JWK_K1, _JWK_K2, _T3),
            ],
        )
        with pytest.raises(LifecycleVerificationError) as exc_info:
            log.snapshot_at(_T4)
        assert exc_info.value.category == LifecycleErrorCategory.TERMINAL_STATE

    def test_revocation_outside_active_rejected(self):
        log = DomainLog(
            domain="agent.example.com",
            events=[
                _issuance(_JWK_K1, _T1),
                RetirementEvent(domain="agent.example.com", timestamp=_T2),
                RevocationEvent(domain="agent.example.com", reason="keyCompromise", timestamp=_T3),
            ],
        )
        with pytest.raises(LifecycleVerificationError) as exc_info:
            log.snapshot_at(_T4)
        assert exc_info.value.category == LifecycleErrorCategory.TERMINAL_STATE

    def test_terminal_state_snapshot_still_returned(self):
        """A prefix ending in a terminal state is valid history."""
        log = DomainLog(
            domain="agent.example.com",
            events=[
                _issuance(_JWK_K1, _T1),
                RevocationEvent(domain="agent.example.com", reason="keyCompromise", timestamp=_T2),
            ],
        )
        snap = log.snapshot_at(_T3)
        assert snap.historical_state == "REVOKED"

    def test_invalid_revocation_reason_rejected(self):
        log = DomainLog(
            domain="agent.example.com",
            events=[
                _issuance(_JWK_K1, _T1),
                RevocationEvent(
                    domain="agent.example.com", reason="ownerRequest", timestamp=_T2
                ),
            ],
        )
        with pytest.raises(LifecycleVerificationError) as exc_info:
            log.snapshot_at(_T3)
        assert exc_info.value.category == LifecycleErrorCategory.INVALID_REVOCATION_REASON

    def test_migration_requires_final_entry_reference(self):
        log = DomainLog(
            domain="agent.example.com",
            events=[
                _issuance(_JWK_K1, _T1),
                MigrationEvent(
                    domain="agent.example.com",
                    previous_log="method-a:stream-1",
                    new_log="method-b:stream-1",
                    final_entry_ref="",
                    timestamp=_T2,
                ),
            ],
        )
        with pytest.raises(LifecycleVerificationError) as exc_info:
            log.snapshot_at(_T3)
        assert exc_info.value.category == LifecycleErrorCategory.INVALID_MIGRATION
        assert exc_info.value.failing_event_index == 1

    def test_migration_requires_different_log(self):
        migration = MigrationEvent(
            domain="agent.example.com",
            previous_log="method-a:stream-1",
            new_log="method-a:stream-1",
            final_entry_ref="method-a:entry-10",
            timestamp=_T2,
        )
        with pytest.raises(LifecycleVerificationError) as exc_info:
            DomainLog(
                "agent.example.com", [_issuance(_JWK_K1, _T1), migration]
            ).snapshot_at(_T3)
        assert exc_info.value.category == LifecycleErrorCategory.INVALID_MIGRATION

    def test_reissuance_without_key_rejected(self):
        """A new issuance must carry its own key; the terminated interval's
        key never carries forward into the new interval."""
        log = DomainLog(
            domain="agent.example.com",
            events=[
                _issuance(_JWK_K1, _T1),
                RetirementEvent(domain="agent.example.com", timestamp=_T2),
                IssuanceEvent(
                    domain="agent.example.com",
                    governance_id="example.com",
                    timestamp=_T3,
                ),  # no key fields
            ],
        )
        with pytest.raises(LifecycleVerificationError) as exc_info:
            log.snapshot_at(_T4)
        assert exc_info.value.category == LifecycleErrorCategory.TERMINAL_STATE

    def test_genesis_issuance_without_key_rejected(self):
        log = DomainLog(
            domain="agent.example.com",
            events=[
                IssuanceEvent(
                    domain="agent.example.com",
                    governance_id="example.com",
                    timestamp=_T1,
                )
            ],
        )
        with pytest.raises(LifecycleVerificationError) as exc_info:
            log.snapshot_at(_T2)
        assert exc_info.value.category == LifecycleErrorCategory.INVALID_ISSUANCE
