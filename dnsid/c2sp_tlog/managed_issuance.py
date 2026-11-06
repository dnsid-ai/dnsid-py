"""Durable coordination of registry-prepared, split-signed ISSUANCE.

The caller owns exclusive storage and publication. This coordinator never appends
locally or enables ACTIVE before exact-byte acceptance and public convergence.
"""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Protocol

from .._utils import normalize_fqdn
from .._verification_budget import remaining_seconds
from ..exceptions import ArgumentError, DNSidError, VerificationError
from ..interfaces import KeyProvider
from ..models import JWK, JWKS, PreparedRegistryEvent, SubmissionResult
from .lr import parse_c2sp_tlog_lr
from .prepared import (
    C2spSignerRole,
    C2spVerificationContext,
    entry_bytes,
    parse_prepared_issuance,
    sign_prepared_event,
)


@dataclass(frozen=True)
class ManagedIssuanceState:
    """Recovery record; completed bytes and the idempotency key never change."""

    domain: str
    governance_id: str
    log_reference: str
    entity_public_key: JWK
    operational_public_key: JWK
    idempotency_key: str
    prepared_entry_bytes: bytes = field(default=b"", repr=False)
    entry_bytes: bytes = field(default=b"", repr=False)
    entry_hash: str = ""
    submission: SubmissionResult | None = None
    last_error_code: str = ""
    terminal_failure: bool = False
    complete: bool = False
    activation_blocked: bool = True


class ManagedIssuanceStore(Protocol):
    """Exclusive durable storage for one operation per identity instance."""

    def create_managed_issuance(self, initial: ManagedIssuanceState) -> ManagedIssuanceState | None:
        """Persist initial atomically, or return the existing operation."""
        ...

    def load_managed_issuance(self, domain: str) -> ManagedIssuanceState | None:
        """Load the authoritative operation."""
        ...

    def persist_managed_issuance(self, state: ManagedIssuanceState) -> None:
        """Durably save a transition while holding exclusive ownership."""
        ...


class ManagedIssuanceRegistry(Protocol):
    """The existing registry preparation and exact-byte submission surface."""

    def prepare_issuance(self, domain: str, idempotency_key: str) -> PreparedRegistryEvent:
        """Return untrusted, partially signed bytes."""
        ...

    def submit_prepared_event(
        self, domain: str, entry_bytes: bytes, idempotency_key: str
    ) -> SubmissionResult:
        """Submit exactly the persisted bytes."""
        ...


class ManagedIssuanceOperationError(DNSidError):
    """Preparation, submission, or persistence failed with retained progress."""

    def __init__(
        self, message: str, issuance: ManagedIssuanceState, *,
        state: str, transient: bool = False, retry_same_bytes: bool = False,
        cause: BaseException | None = None,
    ) -> None:
        """Retain state and structured retry semantics."""
        super().__init__(message)
        self.issuance = copy.deepcopy(issuance)
        self.state = state
        self.transient = transient
        self.retry_same_bytes = retry_same_bytes
        self.error_code = getattr(cause, "error_code", "") or (
            issuance.submission.error_code if issuance.submission else issuance.last_error_code
        )
        self.status_code = getattr(cause, "status_code", None) or (
            issuance.submission.status_code if issuance.submission else None
        )
        self.__cause__ = cause


class ManagedIssuanceInProgressError(DNSidError):
    """A durable operation already owns this identity, including completion."""

    def __init__(self, issuance: ManagedIssuanceState) -> None:
        """Retain the existing operation for explicit resume."""
        super().__init__("managed issuance already exists; resume the durable operation")
        self.issuance = copy.deepcopy(issuance)


def begin_managed_issuance(
    *, domain: str, governance_id: str, log_reference: str, entity_public_key: JWK,
    key_provider: KeyProvider, registry_client: ManagedIssuanceRegistry,
    idempotency_key: str, store: ManagedIssuanceStore,
    set_activation_blocked: Callable[[bool], None],
) -> ManagedIssuanceState:
    """Persist intent, validate preparation, countersign, persist, and submit.

    The caller holds exclusive storage ownership across the entire invocation.
    An existing operation must be resumed, never prepared under a new key.
    """
    _dependencies(store, registry_client, key_provider, set_activation_blocked)
    operational = key_provider.signing_key()
    state = ManagedIssuanceState(
        normalize_fqdn(domain, agent_fqdn=True), normalize_fqdn(governance_id),
        log_reference, entity_public_key, operational, idempotency_key,
    )
    _validate(state, entity_public_key, log_reference)
    existing = store.create_managed_issuance(copy.deepcopy(state))
    if existing is not None:
        raise ManagedIssuanceInProgressError(existing)
    set_activation_blocked(True)
    return _prepare(state, key_provider, registry_client, store)


def resume_managed_issuance(
    *, domain: str, log_reference: str, entity_public_key: JWK,
    key_provider: KeyProvider, registry_client: ManagedIssuanceRegistry,
    store: ManagedIssuanceStore, set_activation_blocked: Callable[[bool], None],
) -> ManagedIssuanceState:
    """Resume authoritative state, without re-signing fixed bytes.

    Completed historical bytes can be recovered without the initial private key.
    The caller separately validates the current application signing binding.
    """
    _dependencies(store, registry_client, key_provider, set_activation_blocked)
    domain = normalize_fqdn(domain, agent_fqdn=True)
    state = store.load_managed_issuance(domain)
    if state is None or state.domain != domain:
        raise ArgumentError("no durable managed issuance exists for this domain")
    _validate(state, entity_public_key, log_reference)
    if state.complete:
        if state.activation_blocked:
            return complete_managed_issuance(domain, store, set_activation_blocked)
        return state
    set_activation_blocked(True)
    if state.submission is not None and state.submission.accepted:
        return state
    if state.terminal_failure or (state.submission and state.submission.state == "rejected"):
        raise ManagedIssuanceOperationError(
            "managed issuance was rejected", state, state="rejected",
        )
    if state.entry_bytes:
        return _submit(state, registry_client, store)
    key = key_provider.signing_key()
    if key.to_dict() != state.operational_public_key.to_dict():
        raise ArgumentError("managed issuance provider no longer matches the persisted key")
    return _prepare(state, key_provider, registry_client, store)


def complete_managed_issuance(
    domain: str, store: ManagedIssuanceStore, set_activation_blocked: Callable[[bool], None],
) -> ManagedIssuanceState:
    """Release activation only after the caller verifies public convergence."""
    if store is None or not callable(set_activation_blocked):
        raise ArgumentError("managed issuance requires storage and activation control")
    state = store.load_managed_issuance(normalize_fqdn(domain, agent_fqdn=True))
    if state is None or state.domain != normalize_fqdn(domain, agent_fqdn=True):
        raise ArgumentError("no durable managed issuance exists for this domain")
    _validate(state, state.entity_public_key, state.log_reference)
    if state.submission is None or not state.submission.accepted:
        raise ArgumentError("managed issuance cannot complete before acceptance")
    if state.complete and not state.activation_blocked:
        return state
    state = _persist(store, replace(state, complete=True, activation_blocked=True))
    try:
        set_activation_blocked(False)
    except Exception as cause:
        raise ManagedIssuanceOperationError(
            "accepted issuance activation is incomplete", state,
            state="accepted", transient=True, cause=cause,
        ) from cause
    return _persist(store, replace(state, activation_blocked=False))


def _dependencies(
    store: ManagedIssuanceStore, registry: ManagedIssuanceRegistry,
    provider: KeyProvider, activation: Callable[[bool], None],
) -> None:
    if store is None or registry is None or provider is None or not callable(activation):
        raise ArgumentError(
            "managed issuance requires store, registry, provider, activation control"
        )


def _context(state: ManagedIssuanceState) -> C2spVerificationContext:
    return C2spVerificationContext(
        fqdn=state.domain, gi=state.governance_id, entity_key=state.entity_public_key,
        operational_key=state.operational_public_key,
    )


def _validate(state: ManagedIssuanceState, entity: JWK, reference: str) -> None:
    from ..exceptions import ValidationError
    from ..registry_client import _validate_tlog_idempotency_key

    _validate_tlog_idempotency_key(state.idempotency_key)
    if normalize_fqdn(state.domain, agent_fqdn=True) != state.domain or (
        normalize_fqdn(state.governance_id) != state.governance_id
    ):
        raise ValidationError("managed issuance identity is not normalized")
    parsed = parse_c2sp_tlog_lr(state.log_reference)
    if parsed.entry_index is not None or parsed.lr != reference:
        raise ValidationError("managed issuance log reference mismatch")
    JWKS([state.entity_public_key]).validate_record_signing()
    JWKS([state.operational_public_key]).validate_operational()
    if state.entity_public_key.thumbprint() != entity.thumbprint() or (
        entity.thumbprint() == state.operational_public_key.thumbprint()
    ):
        raise ValidationError("managed issuance key binding mismatch")
    if not state.activation_blocked and not state.complete:
        raise ValidationError("incomplete issuance must remain activation-blocked")
    if state.prepared_entry_bytes:
        prepared = parse_prepared_issuance(state.prepared_entry_bytes, _context(state))
        if prepared.reference.lr != reference:
            raise ValidationError("managed issuance preparation reference mismatch")
    if not state.entry_bytes:
        if state.entry_hash or state.submission or state.complete:
            raise ValidationError("managed issuance has outcome without completed bytes")
        return
    if hashlib.sha256(state.entry_bytes).hexdigest() != state.entry_hash:
        raise ValidationError("managed issuance entry hash mismatch")
    prepared = parse_prepared_issuance(state.entry_bytes, _context(state))
    if state.prepared_entry_bytes and parse_prepared_issuance(
        state.prepared_entry_bytes, _context(state),
    ).signed_bytes != prepared.signed_bytes:
        raise ValidationError("completed issuance differs from its persisted preparation")
    if prepared.reference.lr != reference or entry_bytes(prepared, _context(state)) != (
        state.entry_bytes
    ):
        raise ValidationError("managed issuance completed bytes mismatch")
    if state.submission is not None:
        _validate_submission(state, state.submission)
    if state.complete and (state.submission is None or not state.submission.accepted):
        raise ValidationError("completed managed issuance requires acceptance")


def _prepare(
    state: ManagedIssuanceState, provider: KeyProvider,
    registry: ManagedIssuanceRegistry, store: ManagedIssuanceStore,
) -> ManagedIssuanceState:
    try:
        remaining_seconds()
        raw = PreparedRegistryEvent(state.prepared_entry_bytes) if state.prepared_entry_bytes else (
            registry.prepare_issuance(state.domain, state.idempotency_key)
        )
        remaining_seconds()
    except Exception as cause:
        transient = (
            not isinstance(cause, VerificationError) or cause.transient
            or getattr(cause, "status_code", None) in {401, 403, 404}
        )
        state = _persist(store, replace(
            state, last_error_code=getattr(cause, "error_code", ""),
            terminal_failure=not transient,
        ))
        raise ManagedIssuanceOperationError(
            "managed issuance preparation failed", state,
            state="prepared" if transient else "rejected", transient=transient, cause=cause,
        ) from cause
    try:
        context = _context(state)
        prepared = parse_prepared_issuance(raw.entry_bytes, context)
        if prepared.reference.lr != state.log_reference or (
            C2spSignerRole.ENTITY in prepared.missing_signatures()
        ):
            raise ArgumentError("issuance preparation has wrong log or no entity signature")
    except Exception as cause:
        transient = isinstance(cause, VerificationError) and cause.transient
        state = _persist(store, replace(state, terminal_failure=not transient))
        raise ManagedIssuanceOperationError(
            "managed issuance preparation failed validation", state,
            state="prepared" if transient else "rejected", transient=transient, cause=cause,
        ) from cause
    state = _persist(store, replace(state, prepared_entry_bytes=raw.entry_bytes))
    try:
        remaining_seconds()
        prepared = sign_prepared_event(
            prepared, C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE, provider, context,
        )
        remaining_seconds()
        completed = entry_bytes(prepared, context)
    except Exception as cause:
        raise ManagedIssuanceOperationError(
            "managed issuance countersigning failed", state,
            state="prepared", transient=True, cause=cause,
        ) from cause
    state = _persist(store, replace(
        state, entry_bytes=completed, entry_hash=hashlib.sha256(completed).hexdigest(),
        last_error_code="", terminal_failure=False,
    ))
    return _submit(state, registry, store)


def _submit(
    state: ManagedIssuanceState, registry: ManagedIssuanceRegistry, store: ManagedIssuanceStore,
) -> ManagedIssuanceState:
    # Persist uncertainty before the request can reach the registry.
    state = _persist(store, replace(state, submission=SubmissionResult(
        state="pending", entry_hash=state.entry_hash,
    )))
    try:
        remaining_seconds()
        result = registry.submit_prepared_event(
            state.domain, state.entry_bytes, state.idempotency_key,
        )
        remaining_seconds()
    except Exception as cause:
        retry = (
            getattr(cause, "status_code", None) in {401, 403, 404}
            or getattr(cause, "retry_same_bytes", True)
        )
        state = _persist(store, replace(
            state, submission=SubmissionResult(
                state="pending" if retry else "rejected", entry_hash=state.entry_hash,
                error_code=getattr(cause, "error_code", ""),
                status_code=getattr(cause, "status_code", None),
            ), terminal_failure=not retry,
        ))
        raise ManagedIssuanceOperationError(
            "managed issuance submission failed", state,
            state="indeterminate" if retry else "rejected", transient=retry,
            retry_same_bytes=retry, cause=cause,
        ) from cause
    try:
        _validate_submission(state, result)
    except Exception as cause:
        raise ManagedIssuanceOperationError(
            "managed issuance receipt failed validation", state,
            state="indeterminate", retry_same_bytes=True, cause=cause,
        ) from cause
    control_plane_failure = result.state == "rejected" and result.status_code in {401, 403, 404}
    if control_plane_failure:
        result = replace(result, state="pending")
    state = _persist(store, replace(
        state, submission=copy.deepcopy(result), last_error_code=result.error_code,
        terminal_failure=result.state == "rejected",
    ))
    if result.state == "rejected" or control_plane_failure:
        raise ManagedIssuanceOperationError(
            "registry did not accept managed issuance bytes", state,
            state="indeterminate" if control_plane_failure else "rejected",
            transient=control_plane_failure, retry_same_bytes=control_plane_failure,
        )
    return state


def _validate_submission(state: ManagedIssuanceState, result: SubmissionResult) -> None:
    from ..exceptions import ValidationError

    if not isinstance(result, SubmissionResult) or result.state not in result.VALID_STATES:
        raise ValidationError("invalid managed issuance submission state")
    if result.entry_hash and result.entry_hash != state.entry_hash:
        raise ValidationError("registry receipt refers to different issuance bytes")
    if not result.accepted:
        return
    if result.entry_hash != state.entry_hash or (
        type(result.index) is not int or result.index < 0 or result.log_ref is None
    ):
        raise ValidationError("accepted issuance lacks exact-byte acceptance facts")
    if str(result.log_ref) != f"{state.log_reference}@{result.index}" or (
        result.key_id and result.key_id != state.operational_public_key.kid
    ):
        raise ValidationError("accepted issuance reference or key mismatch")


def _persist(store: ManagedIssuanceStore, state: ManagedIssuanceState) -> ManagedIssuanceState:
    try:
        remaining_seconds()
        store.persist_managed_issuance(copy.deepcopy(state))
        remaining_seconds()
    except Exception as cause:
        raise ManagedIssuanceOperationError(
            "failed to persist managed issuance", state,
            state=state.submission.state if state.submission else "prepared",
            transient=True, retry_same_bytes=bool(state.entry_bytes), cause=cause,
        ) from cause
    return state
