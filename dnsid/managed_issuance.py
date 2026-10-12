"""Durable split ISSUANCE coordination with application-owned storage/publication."""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field, replace

from ._utils import normalize_fqdn
from ._verification_budget import verification_operation
from .c2sp_tlog import (
    C2spSignerRole,
    C2spVerificationContext,
    PreparedC2spTlogEvent,
    entry_bytes,
    parse_c2sp_tlog_lr,
    parse_prepared_event,
    sign_prepared_event,
)
from .exceptions import ArgumentError, ValidationError
from .interfaces import KeyProvider
from .models import JWK, SubmissionResult
from .registry_client import RegistryClient, _validate_tlog_idempotency_key


@dataclass(frozen=True)
class IssuanceOperation:
    """Persisted intent and exact bytes for one issuance, never a replacement attempt.

    Save the initial intent before publishing DNS, ek, ku, and non-active su.
    Resume with the saved operation after any failure. Storage must commit
    atomically before returning and serialize writers for this identity.
    """

    domain: str
    governance_id: str
    log_reference: str
    entity_key: JWK
    operational_key: JWK
    idempotency_key: str
    entry_bytes: bytes = field(default=b"", repr=False)
    entry_hash: str = ""
    submission: SubmissionResult | None = None
    completed: bool = False


@verification_operation
def resume_issuance(
    operation: IssuanceOperation,
    registry: RegistryClient,
    key_provider: KeyProvider,
    *,
    persist: Callable[[IssuanceOperation], None],
    verify_publication: Callable[[IssuanceOperation], None],
    activate: Callable[[IssuanceOperation], None],
) -> IssuanceOperation:
    """Prepare once, persist exact signed bytes, submit/resume, then activate.

    ``verify_publication`` must verify externally served DNS, ek, ku and su
    against the intent without requiring ACTIVE or an already logged issuance.
    ``activate`` must idempotently converge su to ACTIVE for this accepted
    issuance. Neither hook may create another issuance. On exceptions, reload
    the last committed operation; acceptance is saved before activation.
    """
    if not all(callable(hook) for hook in (persist, verify_publication, activate)):
        raise ArgumentError("issuance requires persistence, publication and activation hooks")
    operation = copy.deepcopy(operation)
    _validate_tlog_idempotency_key(operation.idempotency_key)
    context = C2spVerificationContext(
        fqdn=operation.domain,
        gi=operation.governance_id,
        entity_key=operation.entity_key,
        operational_key=operation.operational_key,
    )
    if not operation.domain or not operation.governance_id:
        raise ArgumentError("issuance requires domain and governance ID")
    if (
        normalize_fqdn(operation.domain, agent_fqdn=True) != operation.domain
        or normalize_fqdn(operation.governance_id) != operation.governance_id
    ):
        raise ValidationError("issuance requires normalized identity domains")
    if operation.entity_key.thumbprint() == operation.operational_key.thumbprint():
        raise ValidationError("issuance entity and operational keys must be distinct")
    reference = parse_c2sp_tlog_lr(operation.log_reference)
    if reference.lr != operation.log_reference or reference.entry_index is not None:
        raise ValidationError("issuance requires a canonical bound log reference")
    selected = key_provider.signing_key()
    expected = operation.operational_key
    if (selected.kid, selected.alg, selected.thumbprint()) != (
        expected.kid,
        expected.alg,
        expected.thumbprint(),
    ):
        raise ValidationError("issuance operational provider changed")

    def save(state: IssuanceOperation) -> None:
        persist(copy.deepcopy(state))

    def validate_prepared(prepared: PreparedC2spTlogEvent) -> None:
        if prepared.envelope["type"] != "ISSUANCE" or prepared.envelope["seq"] != 0:
            raise ValidationError("prepared event is not genesis ISSUANCE")
        for name, key in (("ek", operation.entity_key), ("ku", expected)):
            embedded = JWK.from_dict(prepared.envelope[name])
            if (embedded.kid, embedded.alg, embedded.thumbprint()) != (
                key.kid,
                key.alg,
                key.thumbprint(),
            ):
                raise ValidationError("prepared issuance key metadata changed")

    def validate_entry(state: IssuanceOperation) -> None:
        prepared = parse_prepared_event(state.entry_bytes, state.log_reference, context)
        validate_prepared(prepared)
        entry_bytes(prepared, context)
        if hashlib.sha256(state.entry_bytes).hexdigest() != state.entry_hash:
            raise ValidationError("persisted issuance entry hash mismatch")

    def validate_result(result: SubmissionResult) -> None:
        if result.state not in SubmissionResult.VALID_STATES:
            raise ValidationError("unknown issuance submission state")
        if result.entry_hash and result.entry_hash != operation.entry_hash:
            raise ValidationError("issuance submission entry hash mismatch")
        if result.key_id and result.key_id != expected.kid:
            raise ValidationError("issuance submission key mismatch")
        if result.accepted:
            if result.entry_hash != operation.entry_hash or result.log_ref is None:
                raise ValidationError("accepted issuance requires exact hash and reference")
            accepted = parse_c2sp_tlog_lr(str(result.log_ref))
            if accepted.lr != operation.log_reference or accepted.entry_index is None:
                raise ValidationError("accepted issuance log reference mismatch")
            if result.index is not None and (
                isinstance(result.index, bool)
                or not isinstance(result.index, int)
                or result.index != accepted.entry_index
            ):
                raise ValidationError("accepted issuance index mismatch")

    if operation.entry_bytes:
        validate_entry(operation)
    elif operation.entry_hash or operation.submission or operation.completed:
        raise ValidationError("incomplete persisted issuance")
    if operation.submission is not None:
        validate_result(operation.submission)
    if operation.completed:
        if operation.submission is None or not operation.submission.accepted:
            raise ValidationError("completed issuance requires acceptance")
        return operation
    save(operation)
    if operation.submission is None or not operation.submission.accepted:
        if operation.submission is not None and operation.submission.state == "rejected":
            return operation
        verify_publication(copy.deepcopy(operation))
        if not operation.entry_bytes:
            raw = registry.prepare_issuance(operation.domain, operation.idempotency_key)
            if raw.log_reference != operation.log_reference:
                raise ValidationError("prepared issuance log reference mismatch")
            prepared = parse_prepared_event(raw.entry_bytes, raw.log_reference, context)
            validate_prepared(prepared)
            if prepared.missing_signatures() != [C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE]:
                raise ValidationError("prepared issuance requires an entity signature only")
            signed = sign_prepared_event(
                prepared, C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE, key_provider, context
            )
            data = entry_bytes(signed)
            operation = replace(
                operation, entry_bytes=data, entry_hash=hashlib.sha256(data).hexdigest()
            )
            save(operation)
        result = registry.submit_prepared_event(
            operation.domain, operation.entry_bytes, operation.idempotency_key
        )
        validate_result(result)
        operation = replace(operation, submission=copy.deepcopy(result))
        save(operation)
        if not result.accepted:
            return operation
    activate(copy.deepcopy(operation))
    operation = replace(operation, completed=True)
    save(operation)
    return operation
