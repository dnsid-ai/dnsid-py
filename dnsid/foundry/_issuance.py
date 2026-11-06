"""Adapt the portable Foundry document to shared managed-issuance storage."""

from __future__ import annotations

from dataclasses import fields, replace
from typing import Any

from .._utils import b64url_decode_strict, b64url_encode
from ..c2sp_tlog.managed_issuance import (
    ManagedIssuanceRegistry,
    ManagedIssuanceState,
    issuance_rejected,
)
from ..exceptions import RegistryRequestError
from ..models import JWK, LogRef, PreparedRegistryEvent, SubmissionResult
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


class IssuanceRegistry:
    """Retain control-plane errors before the coordinator persists a transition."""

    def __init__(self, registry: ManagedIssuanceRegistry, store: IssuanceStore) -> None:
        self.registry, self.store = registry, store

    def prepare_issuance(self, domain: str, idempotency_key: str) -> PreparedRegistryEvent:
        self.store.request_error = None
        try:
            return self.registry.prepare_issuance(domain, idempotency_key)
        except RegistryRequestError as error:
            self.store.request_error = error
            raise

    def submit_prepared_event(
        self,
        domain: str,
        entry_bytes: bytes,
        idempotency_key: str,
    ) -> SubmissionResult:
        self.store.request_error = None
        try:
            result = self.registry.submit_prepared_event(domain, entry_bytes, idempotency_key)
        except RegistryRequestError as error:
            self.store.request_error = error
            raise
        if not result.accepted and result.status_code is not None:
            self.store.request_error = RegistryRequestError(
                f"/api/v1/agent/{domain}/tlog/events",
                result.status_code,
                result.error_code,
            )
        return result


class IssuanceStore:
    """Persist coordinator transitions inside the already locked named operation."""

    def __init__(
        self,
        store: FoundryStore,
        key: OperationKey,
        operation: dict[str, Any],
    ) -> None:
        self.store, self.key, self.operation = store, key, operation
        self.request_error: RegistryRequestError | None = None

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
        error, latest = self.request_error, state.submission
        if latest is not None and latest.accepted:
            error = None
        if error is not None and issuance_rejected(error.error_code, error.status_code):
            if latest is not None:
                latest = replace(
                    latest,
                    state="rejected",
                    error_code=error.error_code,
                    status_code=error.status_code,
                )
            state = replace(state, terminal_failure=True, submission=latest)
        if error is not None and not issuance_rejected(error.error_code, error.status_code):
            raw["requestError"] = {"httpStatus": error.status_code, "errorCode": error.error_code}
        elif (
            latest is not None
            and latest.state == "rejected"
            and not (issuance_rejected(latest.error_code, latest.status_code))
        ):
            raw["requestError"] = {"errorCode": latest.error_code}
        else:
            raw.pop("requestError", None)
        if "requestError" in raw:
            if latest is not None and latest.state == "rejected":
                latest = replace(latest, state="pending")
            state = replace(state, terminal_failure=False, submission=latest)
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
