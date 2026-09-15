"""Tests for the entity-key provider and the event signing/write facade.

Covers get_entity_key_set, required_log_signatures, sign_event,
sign_event_with_provider, write_signed_event, and sign_and_write_event
role routing (design: 01-core-identity-manager.md#core-methods).
"""

from __future__ import annotations

import dataclasses
import datetime
import json

import pytest

from dnsid import (
    ArgumentError,
    EventType,
    IdentityManager,
    IdentityManagerDependencies,
    LogRegistry,
    LogSignerRole,
    sign_event_with_provider,
)
from dnsid.interfaces import Log, LogReader
from dnsid.models import (
    AnyLogEvent,
    IssuanceEvent,
    KeyRotationEvent,
    LogEvent,
    LoggedStateEvidence,
    LogRef,
    RevocationEvent,
)
from tests._config import make_config
from tests.conftest import RealKeyProvider, make_ed25519_pair


class InMemoryLog(Log, LogReader):
    """Write-capable log binding with deterministic JSON canonicalization.

    Canonical bytes exclude the signature fields (signing_kid, sig,
    operational_countersig) so adding one role signature never changes the
    bytes covered by another.
    """

    def __init__(self) -> None:
        self.events: list[LogEvent] = []

    def canonical(self, event: LogEvent) -> bytes:
        body = dataclasses.asdict(event)
        for sig_field in ("signing_kid", "sig", "operational_countersig"):
            body.pop(sig_field, None)
        body["event_type"] = str(event.event_type)
        return json.dumps(body, sort_keys=True, default=str).encode()

    def write_event(self, event: LogEvent) -> LogRef:
        if not event.sig:
            raise ArgumentError("unsigned event")
        self.events.append(event)
        return LogRef(method="microledger", entry_ref=str(len(self.events) - 1))

    # LogReader abstract methods — unused in these tests.
    def key_timestamp(self, domain: str, key_thumbprint: str) -> datetime.datetime:
        raise NotImplementedError

    def verify_non_revocation(
        self, domain: str, at: datetime.datetime
    ) -> LoggedStateEvidence:
        raise NotImplementedError

    def read_event(self, ref: LogRef) -> AnyLogEvent:
        raise NotImplementedError

    def rebuild_history(self, domain: str) -> list[AnyLogEvent]:
        raise NotImplementedError


class RotationKeyProvider(RealKeyProvider):
    """RealKeyProvider that can also sign by kid (PreviousOperational)."""

    def sign_key(self, kid: str, payload: bytes) -> bytes:
        private, pub = self._keys[kid]
        from dnsid._crypto import ed25519_sign

        return ed25519_sign(private, payload)


def _verify_ed25519(private, payload: bytes, sig: bytes) -> None:
    private.public_key().verify(sig, payload)


def _b64url_decode(value: str) -> bytes:
    from dnsid._utils import b64url_decode

    return b64url_decode(value)


@pytest.fixture()
def log_binding() -> InMemoryLog:
    return InMemoryLog()


@pytest.fixture()
def registry(log_binding) -> LogRegistry:
    reg = LogRegistry()
    reg.register("microledger", lambda lr: log_binding)
    return reg


def _manager(registry, key_provider, entity_key_provider=None) -> IdentityManager:
    config = make_config(
        domain="agent.example.com",
        governance_id="example.com",
        log_ref="microledger:abc123",
        status_url="https://agent.example.com/status",
    )
    deps = IdentityManagerDependencies(
        log_registry=registry, entity_key_provider=entity_key_provider
    )
    return IdentityManager(config, key_provider, deps)


@pytest.fixture()
def op_pair():
    return make_ed25519_pair("op1")


@pytest.fixture()
def entity_pair():
    return make_ed25519_pair("ent1")


@pytest.fixture()
def op_provider(op_pair):
    private, pub = op_pair
    return RotationKeyProvider("op1", {"op1": (private, pub)})


@pytest.fixture()
def entity_provider(entity_pair):
    private, pub = entity_pair
    return RealKeyProvider("ent1", {"ent1": (private, pub)})


# ---------------------------------------------------------------------------
# get_entity_key_set
# ---------------------------------------------------------------------------


def test_get_entity_key_set_returns_single_current_key(registry, op_provider, entity_provider):
    manager = _manager(registry, op_provider, entity_provider)
    jwks = manager.get_entity_key_set()
    assert [k.kid for k in jwks.keys] == ["ent1"]


def test_get_entity_key_set_requires_provider(registry, op_provider):
    manager = _manager(registry, op_provider)
    with pytest.raises(ArgumentError, match="entity_key_provider"):
        manager.get_entity_key_set()


# ---------------------------------------------------------------------------
# required_log_signatures
# ---------------------------------------------------------------------------


def test_required_log_signatures_by_event_type(registry, op_provider):
    manager = _manager(registry, op_provider)
    assert manager.required_log_signatures(IssuanceEvent(domain="a.example")) == [
        LogSignerRole.ENTITY,
        LogSignerRole.OPERATIONAL_COUNTERSIGNATURE,
    ]
    assert manager.required_log_signatures(KeyRotationEvent(domain="a.example")) == [
        LogSignerRole.PREVIOUS_OPERATIONAL
    ]
    assert manager.required_log_signatures(RevocationEvent(domain="a.example")) == [
        LogSignerRole.ENTITY
    ]


# ---------------------------------------------------------------------------
# sign_and_write_event role routing
# ---------------------------------------------------------------------------


def test_revocation_event_signed_with_entity_key(
    registry, log_binding, op_provider, entity_provider, entity_pair
):
    manager = _manager(registry, op_provider, entity_provider)
    event = RevocationEvent(domain="agent.example.com", reason="keyCompromise")
    manager.sign_and_write_event(event)

    assert event.signing_kid == "ent1"
    entity_private, _ = entity_pair
    _verify_ed25519(entity_private, log_binding.canonical(event), _b64url_decode(event.sig))
    assert log_binding.events == [event]


def test_entity_event_without_entity_provider_fails_before_writing(
    registry, log_binding, op_provider
):
    manager = _manager(registry, op_provider)
    event = RevocationEvent(domain="agent.example.com", reason="keyCompromise")
    with pytest.raises(ArgumentError, match="Entity"):
        manager.sign_and_write_event(event)
    assert log_binding.events == []


def test_issuance_event_carries_entity_and_operational_signatures(
    registry, log_binding, op_provider, op_pair, entity_provider, entity_pair
):
    manager = _manager(registry, op_provider, entity_provider)
    event = IssuanceEvent(domain="agent.example.com", governance_id="example.com")
    manager.sign_and_write_event(event)

    canonical = log_binding.canonical(event)
    entity_private, _ = entity_pair
    op_private, _ = op_pair
    _verify_ed25519(entity_private, canonical, _b64url_decode(event.sig))
    _verify_ed25519(op_private, canonical, _b64url_decode(event.operational_countersig))


def test_key_rotation_signed_by_previous_operational_kid(registry, log_binding):
    prev_private, prev_pub = make_ed25519_pair("prev")
    new_private, new_pub = make_ed25519_pair("new")
    provider = RotationKeyProvider(
        "new", {"new": (new_private, new_pub), "prev": (prev_private, prev_pub)}
    )
    manager = _manager(registry, provider)
    event = KeyRotationEvent(domain="agent.example.com", previous_kid="prev", new_kid="new")
    manager.sign_and_write_event(event)

    assert event.signing_kid == "prev"
    _verify_ed25519(prev_private, log_binding.canonical(event), _b64url_decode(event.sig))


def test_key_rotation_requires_previous_kid(registry, op_provider):
    manager = _manager(registry, op_provider)
    event = KeyRotationEvent(domain="agent.example.com", new_kid="new")
    with pytest.raises(ArgumentError, match="previous_kid"):
        manager.sign_and_write_event(event)


# ---------------------------------------------------------------------------
# Split signing: sign_event / sign_event_with_provider / write_signed_event
# ---------------------------------------------------------------------------


def test_distributed_signing_across_two_single_role_processes(
    registry, log_binding, op_provider, entity_provider
):
    # Machine A holds only the entity key.
    event = IssuanceEvent(domain="agent.example.com", governance_id="example.com")
    sign_event_with_provider(event, LogSignerRole.ENTITY, entity_provider, log_binding)
    assert event.sig and not event.operational_countersig

    # Machine B holds only the operational key and adds its countersignature,
    # then writes through a manager with no entity provider at all.
    manager = _manager(registry, op_provider)
    manager.sign_event(event, LogSignerRole.OPERATIONAL_COUNTERSIGNATURE)
    manager.write_signed_event(event)
    assert log_binding.events == [event]


def test_adding_countersignature_does_not_change_signed_bytes(
    log_binding, entity_provider, op_provider
):
    event = IssuanceEvent(domain="agent.example.com", governance_id="example.com")
    before = log_binding.canonical(event)
    sign_event_with_provider(event, LogSignerRole.ENTITY, entity_provider, log_binding)
    sign_event_with_provider(
        event, LogSignerRole.OPERATIONAL_COUNTERSIGNATURE, op_provider, log_binding
    )
    assert log_binding.canonical(event) == before


def test_write_signed_event_rejects_missing_required_signature(
    registry, log_binding, op_provider, entity_provider
):
    manager = _manager(registry, op_provider, entity_provider)
    event = IssuanceEvent(domain="agent.example.com", governance_id="example.com")
    manager.sign_event(event, LogSignerRole.ENTITY)
    with pytest.raises(ArgumentError, match="OperationalCountersignature"):
        manager.write_signed_event(event)
    assert log_binding.events == []


def test_sign_and_write_preserves_existing_signatures(
    registry, log_binding, op_provider, entity_provider
):
    event = IssuanceEvent(domain="agent.example.com", governance_id="example.com")
    sign_event_with_provider(event, LogSignerRole.ENTITY, entity_provider, log_binding)
    existing_sig = event.sig

    manager = _manager(registry, op_provider)  # no entity provider needed anymore
    manager.sign_and_write_event(event)
    assert event.sig == existing_sig
    assert event.operational_countersig


def test_facade_requires_log_binding(op_provider, entity_provider):
    config = make_config(
        domain="agent.example.com",
        governance_id="example.com",
        log_ref="microledger:abc123",
        status_url="https://agent.example.com/status",
    )
    manager = IdentityManager(
        config,
        op_provider,
        IdentityManagerDependencies(entity_key_provider=entity_provider),
    )
    event = RevocationEvent(domain="agent.example.com", reason="keyCompromise")
    with pytest.raises(ArgumentError):
        manager.canonicalize_log_event(event)
    with pytest.raises(ArgumentError):
        manager.sign_and_write_event(event)


def test_event_type_enum_exposed(registry, op_provider):
    # LogSignerRole is part of the public API surface used by remote signers.
    assert LogSignerRole.ENTITY.value == "Entity"
    assert LogSignerRole.PREVIOUS_OPERATIONAL.value == "PreviousOperational"
    assert EventType.ISSUANCE.value == "ISSUANCE"
