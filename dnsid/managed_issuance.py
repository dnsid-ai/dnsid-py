"""Recoverable registry-managed ISSUANCE using the C2SP log binding."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from typing import Any

from ._utils import normalize_fqdn
from .c2sp_tlog.errors import C2spTlogError
from .c2sp_tlog.lr import parse_c2sp_tlog_lr
from .c2sp_tlog.prepared import (
    C2spSignerRole,
    C2spVerificationContext,
    entry_bytes,
    parse_prepared_event,
    sign_prepared_event,
)
from .enums import VerificationCode
from .exceptions import ArgumentError, DNSidError, VerificationError
from .interfaces import AbstractRegistryClient, KeyProvider
from .models import JWK, JWKS, LogRef, SubmissionResult


@dataclass(frozen=True)
class ManagedIssuanceState:
    """Durable intent, trusted key bindings, exact signed bytes, and append outcome.

    Persist this with :meth:`to_dict` in owner-only atomic storage. Resume with
    :meth:`from_dict`; never replace bytes or keys after an unknown outcome.
    """

    domain: str
    governance_id: str
    log_reference: str
    idempotency_key: str
    entity_thumbprint: str
    operational_thumbprint: str
    entry: bytes = b""
    submission: SubmissionResult | None = None
    terminal_failure: bool = False
    prepared_entry: bytes = b""

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible recovery data (no private keys or credentials)."""
        data = asdict(self)
        data["entry"] = base64.b64encode(self.entry).decode("ascii")
        data["prepared_entry"] = base64.b64encode(self.prepared_entry).decode("ascii")
        if self.submission is not None:
            # Recovery needs typed outcomes, not an untrusted response that may echo secrets.
            data["submission"]["raw"] = {}
            data["submission"]["log_ref"] = (
                str(self.submission.log_ref) if self.submission.log_ref else None
            )
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ManagedIssuanceState:
        """Restore exact bytes and typed submission data from trusted local storage."""
        restored = dict(data)
        restored["entry"] = base64.b64decode(restored["entry"], validate=True)
        restored["prepared_entry"] = base64.b64decode(restored["prepared_entry"], validate=True)
        if restored.get("submission") is not None:
            submission = dict(restored["submission"])
            if submission.get("log_ref"):
                submission["log_ref"] = LogRef.parse(submission["log_ref"])
            restored["submission"] = SubmissionResult(**submission)
        return cls(**restored)


def issue_managed_identity(
    *,
    domain: str,
    governance_id: str,
    log_reference: str,
    entity_key: JWK,
    operational_key_provider: KeyProvider,
    registry_client: AbstractRegistryClient,
    idempotency_key: str,
    persist_issuance: Callable[[ManagedIssuanceState], None],
    issuance: ManagedIssuanceState | None = None,
) -> ManagedIssuanceState:
    """Issue or resume one operation, persisting intent and bytes before writes.

    The caller serializes operations and loads the existing state. Every
    persistence hook must complete durably or raise. Pending results require
    another call with the saved state; accepted/rejected results are not sent
    again. Publication and independent public verification remain separate.
    """
    domain = normalize_fqdn(domain, agent_fqdn=True)
    governance_id = normalize_fqdn(governance_id)
    parse_c2sp_tlog_lr(log_reference)
    if (
        not idempotency_key
        or idempotency_key.strip() != idempotency_key
        or len(idempotency_key) > 200
    ):
        raise ArgumentError(
            "idempotency_key must contain 1 to 200 characters without outer whitespace"
        )
    operational = operational_key_provider.signing_key()
    JWKS([entity_key]).validate_record_signing()
    JWKS([operational]).validate_operational()
    expected = ManagedIssuanceState(
        domain,
        governance_id,
        log_reference,
        idempotency_key,
        entity_key.thumbprint(),
        operational.thumbprint(),
    )
    if expected.entity_thumbprint == expected.operational_thumbprint:
        raise ArgumentError("ISSUANCE requires distinct entity and operational keys")
    if issuance is None:
        issuance = expected
        persist_issuance(issuance)
    elif (
        replace(issuance, entry=b"", prepared_entry=b"", submission=None, terminal_failure=False)
        != expected
    ):
        raise ArgumentError("saved ISSUANCE belongs to another operation or key")
    if issuance.terminal_failure or (
        issuance.submission and issuance.submission.state == "rejected"
    ):
        raise _invalid("saved ISSUANCE was rejected; reconcile before continuing")
    if issuance.submission is not None and not issuance.entry:
        raise _invalid("saved ISSUANCE outcome has no exact bytes; restore recovery state")
    context = C2spVerificationContext(
        entity_key=entity_key,
        operational_key=operational,
        fqdn=domain,
        gi=governance_id,
    )
    if not issuance.entry:
        if not issuance.prepared_entry:
            try:
                raw = registry_client.prepare_issuance(domain, idempotency_key)
            except DNSidError as error:
                if error.status_code is not None and 400 <= error.status_code < 500:
                    persist_issuance(replace(issuance, terminal_failure=True))
                raise
            if raw.log_reference != log_reference:
                persist_issuance(replace(issuance, terminal_failure=True))
                raise _invalid("prepared log reference mismatch")
            issuance = replace(issuance, prepared_entry=raw.entry_bytes)
            persist_issuance(issuance)
        try:
            prepared = parse_prepared_event(issuance.prepared_entry, log_reference, context)
            if prepared.envelope["type"] != "ISSUANCE":
                raise _invalid("expected ISSUANCE")
            if not prepared.envelope.get("sigs", {}).get("ae"):
                raise _invalid("prepared ISSUANCE is missing the entity signature")
            signed = sign_prepared_event(
                prepared,
                C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE,
                operational_key_provider,
                context,
            )
            issuance = replace(issuance, entry=entry_bytes(signed, context))
        except (DNSidError, C2spTlogError, ValueError):
            persist_issuance(replace(issuance, terminal_failure=True))
            raise
        persist_issuance(issuance)
    validate_managed_issuance(issuance, entity_key, operational)
    if issuance.submission is None or not issuance.submission.accepted:
        submitted = registry_client.submit_prepared_event(domain, issuance.entry, idempotency_key)
        issuance = replace(issuance, submission=submitted)
        persist_issuance(issuance)
    validate_managed_issuance(issuance, entity_key, operational)
    return issuance


def validate_managed_issuance(
    issuance: ManagedIssuanceState,
    entity_key: JWK,
    operational_key: JWK,
) -> None:
    """Validate historical recovery bytes/outcomes without needing a private key."""
    if (
        issuance.entity_thumbprint != entity_key.thumbprint()
        or issuance.operational_thumbprint != operational_key.thumbprint()
    ):
        raise _invalid("saved ISSUANCE public key binding mismatch")
    if issuance.terminal_failure:
        raise _invalid("saved ISSUANCE is terminal")
    if issuance.submission is not None and not issuance.entry:
        raise _invalid("saved ISSUANCE outcome has no exact bytes")
    context = C2spVerificationContext(
        entity_key=entity_key,
        operational_key=operational_key,
        fqdn=issuance.domain,
        gi=issuance.governance_id,
    )
    original = None
    if issuance.prepared_entry:
        original = parse_prepared_event(issuance.prepared_entry, issuance.log_reference, context)
        if original.envelope["type"] != "ISSUANCE" or not original.envelope.get("sigs", {}).get(
            "ae"
        ):
            raise _invalid("saved preparation is not entity-signed ISSUANCE")
    if issuance.entry:
        prepared = parse_prepared_event(issuance.entry, issuance.log_reference, context)
        if original is not None:
            signed_envelope = dict(prepared.envelope)
            signed_envelope["sigs"] = {
                name: sig for name, sig in prepared.envelope["sigs"].items() if name != "op"
            }
            original_envelope = dict(original.envelope)
            original_envelope["sigs"] = {
                name: sig for name, sig in original.envelope["sigs"].items() if name != "op"
            }
            if signed_envelope != original_envelope:
                raise _invalid("saved prepared and completed ISSUANCE disagree")
        if (
            prepared.envelope["type"] != "ISSUANCE"
            or entry_bytes(prepared, context) != issuance.entry
        ):
            raise _invalid("saved bytes are not a complete canonical ISSUANCE")
    result = issuance.submission
    if result is None:
        return
    if result.state not in SubmissionResult.VALID_STATES:
        raise _invalid("invalid ISSUANCE submission state")
    if result.state == "rejected":
        raise _invalid("registry rejected ISSUANCE")
    if result.accepted and (
        result.entry_hash != hashlib.sha256(issuance.entry).hexdigest()
        or type(result.index) is not int
        or result.index < 0
        or str(result.log_ref) != f"{issuance.log_reference}@{result.index}"
    ):
        raise _invalid("accepted ISSUANCE hash, index, or final reference mismatch")


def _invalid(message: str) -> VerificationError:
    return VerificationError(VerificationCode.LOG_ERROR, message)
