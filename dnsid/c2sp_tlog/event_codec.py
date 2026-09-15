"""Conversion between DNSid log events and C2SP JSON entry envelopes.

The envelope is canonical JCS JSON:
``{"v":1,"kind":"dnsid.lifecycle","type":...,"fqdn":...,"ts":...,...,"sigs":{...}}``.
Signatures cover the envelope bytes with the ``sigs`` member removed.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass
from typing import Any

from .._crypto import jwk_from_dict
from .._utils import b64url_decode_strict, b64url_encode, normalize_fqdn
from ..models import (
    JWK,
    AnyLogEvent,
    DelegationEvent,
    IssuanceEvent,
    KeyRotationEvent,
    MigrationEvent,
    RetirementEvent,
    RevocationEvent,
)
from .canonical import (
    _MAX_SAFE_INT,
    assert_canonical_json_bytes,
    canonical_bytes,
    parse_json_no_duplicate_members,
)
from .errors import C2spTlogParseError
from .merkle import sha256

_MAX_ENTRY_BYTES = 0xFFFF
_SUPPORTED = frozenset(
    ["ISSUANCE", "KEY_ROTATION", "REVOCATION", "RETIREMENT", "MIGRATION", "DELEGATION"]
)
_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_REVOCATION_REASONS = frozenset(
    ["keyCompromise", "policyViolation", "superseded", "cessationOfOperation"]
)


@dataclass
class C2spEventContext:
    """Stream context stamped into (and validated against) public entries."""

    scope: str | None = None
    log_origin: str | None = None
    stream_id: str | None = None
    lr: str | None = None
    seq: int | None = None
    prev_event_id: str | None = None
    prev_state_hash: str | None = None


@dataclass
class C2spSignatureValue:
    """One member of an entry's sigs object: signer key ID plus signature."""

    kid: str
    sig: str


def event_to_c2sp_envelope(
    event: AnyLogEvent,
    context: C2spEventContext | None = None,
    include_sigs: bool = True,
) -> dict[str, Any]:
    """Build the C2SP JSON envelope for *event*."""
    ctx = context or C2spEventContext()
    obj: dict[str, Any] = {
        "v": 1,
        "kind": "dnsid.lifecycle",
        "type": str(event.event_type),
        "fqdn": event.domain,
        "ts": _epoch_seconds(event.timestamp, "timestamp"),
    }
    if isinstance(event, IssuanceEvent):
        entity_key, operational_key = _require_issuance_keys(event)
        obj["gi"] = event.governance_id
        obj["ek"] = dict(entity_key._raw)
        obj["ku"] = dict(operational_key._raw)
    elif isinstance(event, KeyRotationEvent):
        if event.new_public_key is None:
            raise C2spTlogParseError("KEY_ROTATION is missing new_public_key")
        obj["prev_thumb"] = event.previous_thumbprint
        obj["new_ku"] = dict(event.new_public_key._raw)
        obj["new_thumb"] = event.new_thumbprint
    elif isinstance(event, RevocationEvent):
        obj["reason"] = event.reason
    elif isinstance(event, RetirementEvent):
        pass
    elif isinstance(event, MigrationEvent):
        obj["prev_lr"] = event.previous_log
        obj["new_lr"] = event.new_log
        obj["prev_ref"] = event.final_entry_ref
    elif isinstance(event, DelegationEvent):
        obj["delegatee"] = event.delegatee
        obj["scope"] = event.scope
        obj["expiry"] = _epoch_seconds(event.expiry, "expiry")
    else:
        raise C2spTlogParseError(
            f"{event.event_type} is not supported by c2sp-tlog version 1"
        )
    if ctx.scope == "public" or ctx.log_origin or ctx.stream_id or ctx.lr:
        obj["method"] = "c2sp-tlog"
        if ctx.log_origin:
            obj["log_origin"] = ctx.log_origin
        if ctx.stream_id:
            obj["stream_id"] = ctx.stream_id
        if ctx.lr:
            obj["lr"] = ctx.lr
    if ctx.seq is not None:
        obj["seq"] = ctx.seq
    if ctx.prev_event_id is not None:
        obj["prev_event_id"] = ctx.prev_event_id
    if ctx.prev_state_hash:
        obj["prev_state_hash"] = ctx.prev_state_hash
    _validate_public_fields(obj, ctx)
    if include_sigs:
        sigs = _signatures_from_event(event)
        if sigs:
            obj["sigs"] = sigs
    return obj


def c2sp_envelope_to_event(obj: object) -> AnyLogEvent:
    """Parse a C2SP JSON envelope into the corresponding DNSid event."""
    if not isinstance(obj, dict):
        raise C2spTlogParseError("C2SP event entry must be an object")
    e: dict[str, Any] = obj
    if e.get("v") != 1 or e.get("kind") != "dnsid.lifecycle":
        raise C2spTlogParseError("unsupported C2SP event envelope")
    if "method" in e and e.get("method") != "c2sp-tlog":
        raise C2spTlogParseError("C2SP event method mismatch")
    type_ = _as_str(e.get("type"), "type")
    if type_ not in _SUPPORTED:
        raise C2spTlogParseError(f"unsupported DNSid lifecycle event type: {type_}")
    timestamp = _date_from_seconds(_as_safe_int(e.get("ts"), "ts"), "ts")
    domain = _as_str(e.get("fqdn"), "fqdn")
    sigs = _parse_signatures(e.get("sigs"), type_)

    if type_ == "ISSUANCE":
        entity_key = _as_jwk(e.get("ek"), "ek")
        operational_key = _as_jwk(e.get("ku"), "ku")
        ae, op = sigs["ae"], sigs["op"]
        if ae.kid != entity_key.kid or op.kid != operational_key.kid:
            raise C2spTlogParseError("ISSUANCE signature kid does not match recorded key")
        return IssuanceEvent(
            domain=domain,
            governance_id=_as_str(e.get("gi"), "gi"),
            timestamp=timestamp,
            entity_key=entity_key,
            operational_key=operational_key,
            signing_kid=ae.kid,
            sig=ae.sig,
            operational_countersig=op.sig,
        )
    if type_ == "KEY_ROTATION":
        new_key = _as_jwk(e.get("new_ku"), "new_ku")
        prev_op, new_op = sigs["prev_op"], sigs["new_op"]
        if new_op.kid != new_key.kid:
            raise C2spTlogParseError("KEY_ROTATION new_op kid does not match new_ku")
        return KeyRotationEvent(
            domain=domain,
            timestamp=timestamp,
            previous_kid=prev_op.kid,
            previous_thumbprint=_as_str(e.get("prev_thumb"), "prev_thumb"),
            new_kid=new_key.kid,
            new_public_key=new_key,
            new_thumbprint=_as_str(e.get("new_thumb"), "new_thumb"),
            signing_kid=prev_op.kid,
            sig=prev_op.sig,
            new_operational_proof=new_op.sig,
        )
    ae = sigs["ae"]
    if type_ == "REVOCATION":
        return RevocationEvent(
            domain=domain,
            timestamp=timestamp,
            reason=_as_revocation_reason(e.get("reason")),
            signing_kid=ae.kid,
            sig=ae.sig,
        )
    if type_ == "RETIREMENT":
        return RetirementEvent(
            domain=domain, timestamp=timestamp, signing_kid=ae.kid, sig=ae.sig
        )
    if type_ == "MIGRATION":
        return MigrationEvent(
            domain=domain,
            timestamp=timestamp,
            previous_log=_as_str(e.get("prev_lr"), "prev_lr"),
            new_log=_as_str(e.get("new_lr"), "new_lr"),
            final_entry_ref=_as_str(e.get("prev_ref"), "prev_ref"),
            signing_kid=ae.kid,
            sig=ae.sig,
        )
    # DELEGATION
    return DelegationEvent(
        domain=domain,
        timestamp=timestamp,
        delegatee=_as_str(e.get("delegatee"), "delegatee"),
        scope=_as_str(e.get("scope"), "scope"),
        expiry=_date_from_seconds(_as_safe_int(e.get("expiry"), "expiry"), "expiry"),
        signing_kid=ae.kid,
        sig=ae.sig,
    )


def parse_c2sp_event_entry(
    data: bytes, context: C2spEventContext | None = None, *, candidate: bool = False
) -> AnyLogEvent:
    """Parse an entry; scans defer signed chain errors until after authentication."""
    _assert_entry_size(data)
    obj = parse_json_no_duplicate_members(data)
    assert_canonical_json_bytes(data, obj)
    _validate_public_fields(obj, context or C2spEventContext())
    if not candidate:
        from .prepared import _assert_public_chain_shape
        _assert_public_chain_shape(obj)
    return c2sp_envelope_to_event(obj)


def parse_chain_fields(obj: object) -> dict[str, int | str]:
    """Extract validated chain fields (seq/prev_*) from a parsed envelope."""
    if not isinstance(obj, dict):
        raise C2spTlogParseError("C2SP event entry must be an object")
    out: dict[str, int | str] = {}
    if "seq" in obj:
        out["seq"] = _as_safe_int(obj.get("seq"), "seq")
    if any(name in obj for name in ("event_id", "prev_index", "prev_leaf_hash")):
        raise C2spTlogParseError("prohibited logical-chain field")
    for name in ("prev_event_id", "prev_state_hash"):
        if name in obj:
            value = _as_str(obj[name], name)
            decoded = b64url_decode_strict(value)
            if len(decoded) != 32 or b64url_encode(decoded) != value:
                raise C2spTlogParseError(f"{name} must be a canonical 32-byte hash")
            out[name] = value
    return out


def signed_c2sp_entry_bytes(data: bytes) -> bytes:
    """Return the signed byte form of a stored entry: the envelope minus sigs."""
    _assert_entry_size(data)
    obj = parse_json_no_duplicate_members(data)
    assert_canonical_json_bytes(data, obj)
    if not isinstance(obj, dict):
        raise C2spTlogParseError("C2SP event entry must be an object")
    copy = dict(obj)
    copy.pop("sigs", None)
    return canonical_bytes(copy)


def c2sp_event_id(data: bytes) -> str:
    """Derive logical identity without altering exact-entry inclusion evidence."""
    return b64url_encode(sha256(b"dnsid-c2sp-event-v1\x00", signed_c2sp_entry_bytes(data)))


def canonicalize_c2sp_event(
    event: AnyLogEvent, context: C2spEventContext | None = None
) -> bytes:
    """Canonical stored form of *event* including signatures."""
    envelope = event_to_c2sp_envelope(event, context, include_sigs=True)
    _parse_signatures(envelope.get("sigs"), str(event.event_type))
    data = canonical_bytes(envelope)
    _assert_entry_size(data)
    return data


def signed_c2sp_event_bytes(
    event: AnyLogEvent, context: C2spEventContext | None = None
) -> bytes:
    """Canonical byte form of *event* that signatures cover (no sigs member)."""
    return canonical_bytes(event_to_c2sp_envelope(event, context, include_sigs=False))


def prepare_c2sp_tlog_event(
    event: AnyLogEvent, context: C2spEventContext
) -> dict[str, Any]:
    """Build the unsigned envelope for an event about to be signed and appended."""
    obj = event_to_c2sp_envelope(event, context, include_sigs=False)
    _validate_public_fields(obj, context)
    return obj


def _signatures_from_event(event: AnyLogEvent) -> dict[str, dict[str, str]]:
    if isinstance(event, IssuanceEvent):
        entity_key, operational_key = _require_issuance_keys(event)
        sigs: dict[str, dict[str, str]] = {}
        if event.sig:
            sigs["ae"] = {"kid": event.signing_kid or entity_key.kid, "sig": event.sig}
        if event.operational_countersig:
            sigs["op"] = {
                "kid": operational_key.kid,
                "sig": event.operational_countersig,
            }
        return sigs
    if isinstance(event, KeyRotationEvent):
        sigs = {}
        if event.sig:
            sigs["prev_op"] = {
                "kid": event.signing_kid or event.previous_kid,
                "sig": event.sig,
            }
        if event.new_operational_proof:
            sigs["new_op"] = {"kid": event.new_kid, "sig": event.new_operational_proof}
        return sigs
    if event.sig:
        return {"ae": {"kid": event.signing_kid or "", "sig": event.sig}}
    return {}


def _require_issuance_keys(event: IssuanceEvent) -> tuple[JWK, JWK]:
    if event.entity_key is None or event.operational_key is None:
        raise C2spTlogParseError("ISSUANCE is missing c2sp-tlog key metadata")
    if not event.entity_key.kid or not event.operational_key.kid:
        raise C2spTlogParseError("ISSUANCE is missing c2sp-tlog key metadata")
    return event.entity_key, event.operational_key


def required_c2sp_signature_names(type_: str) -> list[str]:
    """Return the sigs member names a complete entry of *type_* must carry."""
    if type_ == "ISSUANCE":
        return ["ae", "op"]
    if type_ == "KEY_ROTATION":
        return ["prev_op", "new_op"]
    if type_ in _SUPPORTED:
        return ["ae"]
    raise C2spTlogParseError(f"unsupported DNSid lifecycle event type: {type_}")


def parse_c2sp_signatures(
    value: object, type_: str, require_complete: bool = True
) -> dict[str, C2spSignatureValue]:
    """Parse an entry's sigs object into signature values keyed by role.

    Partial signature sets are allowed when *require_complete* is False
    (prepared events mid-collection).

    Raises:
        C2spTlogParseError: If *type_* is unsupported, the object is missing
            or malformed, a role is unexpected, or (when *require_complete*
            is True) a required signature is absent.
    """
    if value is None and not require_complete:
        return {}
    if not isinstance(value, dict):
        raise C2spTlogParseError("C2SP event missing sigs object")
    allowed = required_c2sp_signature_names(type_)
    for key in value:
        if key not in allowed:
            raise C2spTlogParseError(f"unexpected signature role: {key}")
    parsed: dict[str, C2spSignatureValue] = {}
    for key in allowed:
        raw = value.get(key)
        if raw is None:
            if require_complete:
                raise C2spTlogParseError(f"missing sigs.{key}")
            continue
        parsed[key] = _parse_signature_value(raw, f"sigs.{key}")
    return parsed


def _parse_signatures(value: object, type_: str) -> dict[str, C2spSignatureValue]:
    return parse_c2sp_signatures(value, type_, require_complete=True)


def _parse_signature_value(value: object, name: str) -> C2spSignatureValue:
    if not isinstance(value, dict):
        raise C2spTlogParseError(f"{name} must be an object")
    for key in value:
        if key not in ("kid", "sig"):
            raise C2spTlogParseError(f"{name} contains an unknown member")
    kid = _as_str(value.get("kid"), f"{name}.kid")
    sig = _as_str(value.get("sig"), f"{name}.sig")
    if not _SIGNATURE_RE.fullmatch(sig):
        raise C2spTlogParseError(f"{name}.sig must be unpadded base64url")
    try:
        if b64url_encode(b64url_decode_strict(sig)) != sig:
            raise ValueError("noncanonical signature")
    except ValueError as exc:
        raise C2spTlogParseError(f"{name}.sig must be canonical base64url") from exc
    return C2spSignatureValue(kid=kid, sig=sig)


def _validate_public_fields(obj: object, context: C2spEventContext) -> None:
    if not isinstance(obj, dict):
        raise C2spTlogParseError("C2SP event entry must be an object")
    if type(obj.get("v")) is not int or obj["v"] != 1:
        raise C2spTlogParseError("unsupported C2SP envelope version")
    fqdn = normalize_fqdn(_as_str(obj.get("fqdn"), "fqdn"), agent_fqdn=True)
    if fqdn != obj["fqdn"] or obj.get("stream_id") == fqdn:
        raise C2spTlogParseError(
            "C2SP requires normalized FQDN and identity-instance stream ID, not the bare FQDN"
        )
    from .lr import parse_c2sp_tlog_lr
    reference = parse_c2sp_tlog_lr(_as_str(obj.get("lr"), "lr"))
    if (reference.entry_index is not None or reference.lr != obj["lr"]
            or (context.scope is not None and context.scope != reference.scope)
            or reference.origin != obj.get("log_origin")
            or reference.stream_id != obj.get("stream_id")):
        raise C2spTlogParseError("C2SP signed context mismatch")
    expected: dict[str, str | None] = {
        "method": "c2sp-tlog",
        "log_origin": context.log_origin,
        "stream_id": context.stream_id,
        "lr": context.lr,
    }
    for k in ("method", "log_origin", "stream_id", "lr"):
        v = obj.get(k)
        if not isinstance(v, str) or not v:
            raise C2spTlogParseError(f"public C2SP event missing signed {k}")
        if expected[k] is not None and v != expected[k]:
            raise C2spTlogParseError(f"public C2SP event {k} mismatch")


def _epoch_seconds(ts: datetime.datetime, name: str) -> int:
    if ts.tzinfo is None:
        raise C2spTlogParseError(f"{name} must be timezone-aware")
    millis = ts.timestamp() * 1000
    if millis < 0 or millis != int(millis) or int(millis) % 1000 != 0:
        raise C2spTlogParseError(f"{name} must have whole-second precision")
    return int(millis) // 1000


def _date_from_seconds(seconds: int, name: str) -> datetime.datetime:
    try:
        return datetime.datetime.fromtimestamp(seconds, tz=datetime.UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise C2spTlogParseError(f"{name} outside date range") from exc


def _as_str(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise C2spTlogParseError(f"missing {name}")
    return value


def _as_safe_int(value: object, name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_SAFE_INT
    ):
        raise C2spTlogParseError(f"{name} outside safe integer range")
    return value


def _as_jwk(value: object, name: str) -> JWK:
    if not isinstance(value, dict):
        raise C2spTlogParseError(f"missing {name}")
    _as_str(value.get("kty"), f"{name}.kty")
    _as_str(value.get("kid"), f"{name}.kid")
    _as_str(value.get("alg"), f"{name}.alg")
    return jwk_from_dict(value)


def _as_revocation_reason(value: object) -> str:
    if not isinstance(value, str) or value not in _REVOCATION_REASONS:
        raise C2spTlogParseError("invalid REVOCATION reason")
    return value


def _assert_entry_size(data: bytes) -> None:
    if len(data) == 0 or len(data) > _MAX_ENTRY_BYTES:
        raise C2spTlogParseError("C2SP entry must be between 1 and 65535 bytes")
