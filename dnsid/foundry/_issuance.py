"""Adapt the portable Foundry document to shared managed-issuance storage."""

from __future__ import annotations

from dataclasses import fields
from typing import Any

from .._utils import b64url_decode_strict, b64url_encode
from ..c2sp_tlog.managed_issuance import ManagedIssuanceState
from ..models import JWK, LogRef, SubmissionResult
from .errors import FoundryStateError
from .store import FoundryStore, OperationKey

_FIELDS = {
    "domain": "domain",
    "governance_id": "governanceId",
    "log_reference": "logReference",
    "entity_public_key": "entityPublicKey",
    "operational_public_key": "operationalPublicKey",
    "idempotency_key": "idempotencyKey",
    "entry_bytes": "entryBytes",
    "entry_hash": "entryHash",
    "prepared_entry_bytes": "preparedEntryBytes",
    "last_error_code": "lastErrorCode",
    "terminal_failure": "terminalFailure",
    "complete": "complete",
    "activation_blocked": "activationBlocked",
}


class IssuanceStore:
    """Persist coordinator transitions inside the already locked named operation."""

    def __init__(
        self,
        store: FoundryStore,
        key: OperationKey,
        operation: dict[str, Any],
    ) -> None:
        self.store, self.key, self.operation = store, key, operation

    def create_managed_issuance(self, initial: ManagedIssuanceState) -> ManagedIssuanceState | None:
        existing = self.load_managed_issuance(initial.domain)
        if existing is not None:
            return existing
        self.persist_managed_issuance(initial)
        return None

    def load_managed_issuance(self, domain: str) -> ManagedIssuanceState | None:
        raw = self.operation.get("issuance")
        if raw is None:
            return None
        return decode_issuance(raw, domain)

    def persist_managed_issuance(self, state: ManagedIssuanceState) -> None:
        raw = dict(self.operation.get("issuance", {}))
        for field in fields(state):
            if field.name == "submission":
                continue
            value = getattr(state, field.name)
            if value is None or value == "":
                raw.pop(_FIELDS[field.name], None)
                continue
            if isinstance(value, JWK):
                value = value.to_dict()
            elif isinstance(value, bytes):
                if not value:
                    raw.pop(_FIELDS[field.name], None)
                    continue
                value = b64url_encode(value)
            raw[_FIELDS[field.name]] = value
        if state.submission is not None:
            submission = dict(raw.get("submission", {}))
            submission.update(state=state.submission.state)
            for member, value in (
                ("entryHash", state.submission.entry_hash),
                ("index", state.submission.index),
                ("logRef", str(state.submission.log_ref) if state.submission.log_ref else None),
                ("keyId", state.submission.key_id),
                ("errorCode", state.submission.error_code),
                ("httpStatus", state.submission.status_code),
            ):
                if value is not None and value != "":
                    submission[member] = value
                else:
                    submission.pop(member, None)
            raw["submission"] = submission
        self.operation["issuance"] = raw
        if state.submission is not None and state.submission.accepted:
            self.operation["phase"] = "issuance-accepted"
        self.store.save(self.key, self.operation)


def decode_issuance(raw: dict[str, Any], domain: str) -> ManagedIssuanceState:
    """Decode portable state without trusting its bindings or signatures."""
    try:
        values = {name: raw[member] for name, member in _FIELDS.items() if member in raw}
        for name in ("entity_public_key", "operational_public_key"):
            values[name] = JWK.from_dict(values[name])
        for name in ("entry_bytes", "prepared_entry_bytes"):
            if name in values:
                values[name] = b64url_decode_strict(values[name])
        if "submission" in raw:
            submission = raw["submission"]
            values["submission"] = SubmissionResult(
                state=submission["state"],
                entry_hash=submission.get("entryHash", ""),
                index=submission.get("index"),
                log_ref=LogRef.parse(submission["logRef"]) if "logRef" in submission else None,
                key_id=submission.get("keyId", ""),
                error_code=submission.get("errorCode", ""),
                status_code=submission.get("httpStatus"),
            )
        for name in ("terminal_failure", "complete", "activation_blocked"):
            if name in values and type(values[name]) is not bool:
                raise ValueError("issuance flags must be boolean")
        result = ManagedIssuanceState(**values)
        if result.domain != domain:
            raise ValueError("issuance belongs to another domain")
        return result
    except Exception as cause:
        raise FoundryStateError("invalid saved issuance", cause=cause) from cause
