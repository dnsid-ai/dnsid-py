"""Prepared-event model: role-based split signing of C2SP entries.

A ``PreparedC2spTlogEvent`` carries the envelope (including any unknown signed
fields), the exact bytes lifecycle signatures cover, and the signer roles still
required.  Processes that each hold only one signer role exchange prepared
bytes, validate them as untrusted input, and add exactly their own signature —
no process needs the other's private key.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .._utils import b64url_decode, b64url_encode, normalize_fqdn
from ..interfaces import KeyProvider
from ..models import JWK, AnyLogEvent, LogRef
from .canonical import (
    assert_canonical_json_bytes,
    canonical_bytes,
    parse_json_no_duplicate_members,
)
from .errors import C2spTlogParseError, C2spTlogVerificationError
from .event_codec import (
    C2spEventContext,
    _validate_public_fields,
    event_to_c2sp_envelope,
    parse_c2sp_event_entry,
    parse_c2sp_signatures,
    required_c2sp_signature_names,
)
from .lr import ParsedC2spTlogLr, parse_c2sp_tlog_lr


class C2spSignerRole(enum.Enum):
    """Lifecycle signer roles for c2sp-tlog envelopes.

    The first three reuse their shared DNSid meanings; NEW_OPERATIONAL is
    owned by this binding and is only the KEY_ROTATION proof of possession.
    """

    ENTITY = "Entity"
    OPERATIONAL_COUNTERSIGNATURE = "OperationalCountersignature"
    PREVIOUS_OPERATIONAL = "PreviousOperational"
    NEW_OPERATIONAL = "NewOperational"


_ROLE_TO_SIGNATURE: dict[C2spSignerRole, str] = {
    C2spSignerRole.ENTITY: "ae",
    C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE: "op",
    C2spSignerRole.PREVIOUS_OPERATIONAL: "prev_op",
    C2spSignerRole.NEW_OPERATIONAL: "new_op",
}
_SIGNATURE_TO_ROLE: dict[str, C2spSignerRole] = {
    v: k for k, v in _ROLE_TO_SIGNATURE.items()
}


def required_signer_roles(event_type: str) -> list[C2spSignerRole]:
    """Return the signer roles a complete entry of *event_type* must carry."""
    return [
        _SIGNATURE_TO_ROLE[name] for name in required_c2sp_signature_names(event_type)
    ]


@dataclass
class C2spChain:
    """Logical stream-chain metadata required in every scope."""

    sequence: int
    previous_event_id: str | None = None
    previous_state_hash: str | None = None


@dataclass
class C2spVerificationContext:
    """Expected identity and trusted keys for validating a prepared envelope.

    A process that countersigns a prepared event (notably the operational side
    of a split ISSUANCE) supplies what it expects the envelope to authorize —
    its own ``fqdn``/``gi``/``operational_key`` and, when known, the trusted
    ``entity_key`` — so a malicious preparer cannot obtain a signature for
    an unexpected identity. ``new_lr`` pins a MIGRATION destination. Only
    ISSUANCE carries ``gi``; other events require independent trusted chain
    validation to bind them to a governance identity.
    """

    entity_key: JWK | None = None
    previous_operational_key: JWK | None = None
    operational_key: JWK | None = None
    fqdn: str | None = None
    gi: str | None = None
    new_lr: str | None = None


@dataclass
class PreparedC2spTlogEvent:
    """An envelope prepared for split signing.

    Treated as immutable apart from adding a role signature (via
    :func:`sign_prepared_event`, which returns a new instance).  ``envelope``
    preserves unknown signed fields; ``signed_bytes`` is the canonical JCS of
    the envelope with the top-level ``sigs`` member removed.
    """

    reference: ParsedC2spTlogLr
    envelope: dict[str, Any] = field(repr=False)
    signed_bytes: bytes = field(repr=False)
    required_signatures: list[C2spSignerRole] = field(default_factory=list)

    def missing_signatures(self) -> list[C2spSignerRole]:
        """Roles still absent from the envelope's sigs object."""
        sigs = self.envelope.get("sigs")
        present = set(sigs.keys()) if isinstance(sigs, dict) else set()
        return [
            r for r in self.required_signatures if _ROLE_TO_SIGNATURE[r] not in present
        ]


def prepare_event(
    event: AnyLogEvent, lr: str, chain: C2spChain | None = None
) -> PreparedC2spTlogEvent:
    """Build the unsigned prepared form of *event* bound to *lr*.

    Any signatures already on *event* are discarded: they cannot be proven to
    cover the resulting envelope.  Preparation requires no private key.  For
    every scope, ISSUANCE (and inbound MIGRATION) genesis derives ``seq=0``
    and rejects prior-chain fields; every later event requires *chain*.
    """
    reference = _bound_reference(lr)
    _reject_bare_fqdn_writer_stream(reference, event.domain)
    normalized = _prepare_chain(event, reference, chain)
    context = C2spEventContext(
        scope=reference.scope,
        log_origin=reference.origin,
        stream_id=reference.stream_id,
        lr=reference.lr,
        seq=normalized.sequence if normalized else None,
        prev_event_id=normalized.previous_event_id if normalized else None,
        prev_state_hash=normalized.previous_state_hash if normalized else None,
    )
    envelope = event_to_c2sp_envelope(event, context, include_sigs=False)
    return _make_prepared(reference, _assert_prepared_envelope(envelope, reference))


def parse_prepared_event(
    data: bytes,
    lr: str,
    context: C2spVerificationContext | None = None,
) -> PreparedC2spTlogEvent:
    """Parse prepared bytes received from another process as untrusted input.

    Requires canonical JCS with no duplicate members, validates the envelope
    and its signed context against *lr*, preserves unknown signed fields, and
    validates every signature already present before the result may be given
    another signature.  For roles whose key is not embedded in the envelope,
    the corresponding trusted key must be supplied via *context*; a signature
    whose key cannot be resolved fails closed.
    """
    _assert_entry_size(data)
    reference = _bound_reference(lr)
    obj = parse_json_no_duplicate_members(data)
    assert_canonical_json_bytes(data, obj)
    if not isinstance(obj, dict):
        raise C2spTlogParseError("prepared C2SP event must be an object")
    envelope = _assert_prepared_envelope(obj, reference)
    _reject_bare_fqdn_writer_stream(reference, str(envelope.get("fqdn", "")))
    prepared = _make_prepared(reference, envelope)
    ctx = context or C2spVerificationContext()
    _assert_expected_identity(prepared, ctx)
    _verify_existing_signatures(prepared, ctx)
    return prepared


def sign_prepared_event(
    prepared: PreparedC2spTlogEvent,
    role: C2spSignerRole,
    key_provider: KeyProvider,
    context: C2spVerificationContext | None = None,
    *,
    replace_existing: bool = False,
) -> PreparedC2spTlogEvent:
    """Sign *prepared* for *role* and return a new prepared event.

    The provider's key for the role's kid must match the key the envelope (or
    trusted *context*) requires for *role* by kid, alg, and RFC 7638
    thumbprint.  Only the requested signature is added; an existing signature
    for the role is never replaced unless *replace_existing* is set. Entity
    signers must inspect/approve the entire prepared envelope (including
    reason, delegatee, scope, expiry and chain fields) before signing: the
    identity context alone cannot authorize the event's action.
    """
    _assert_prepared_integrity(prepared)
    if role not in prepared.required_signatures:
        raise C2spTlogVerificationError(
            f"{role.value} is not required for {prepared.envelope.get('type')}"
        )
    ctx = context or C2spVerificationContext()
    if role is C2spSignerRole.ENTITY and prepared.envelope.get("type") != "ISSUANCE":
        if not ctx.fqdn:
            raise C2spTlogVerificationError(
                "Entity signing requires the expected fqdn for non-ISSUANCE events"
            )
        if prepared.envelope.get("type") == "MIGRATION" and not ctx.new_lr:
            raise C2spTlogVerificationError(
                "Entity signing a MIGRATION requires the expected new_lr"
            )
    if role is C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE:
        # Countersigning an ISSUANCE authorizes an identity binding, so the
        # signer must state the complete identity it intends to authorize —
        # optional checks would let a malicious issuer's envelope pass
        # unexamined (design doc 11 §Split ISSUANCE Flow, step 4).
        missing = [
            name
            for name, present in (
                ("fqdn", ctx.fqdn is not None),
                ("gi", ctx.gi is not None),
                ("entity_key", ctx.entity_key is not None),
                ("operational_key", ctx.operational_key is not None),
            )
            if not present
        ]
        if missing:
            raise C2spTlogVerificationError(
                "operational countersigning requires the complete expected "
                f"identity context; missing: {', '.join(missing)}"
            )
    _assert_expected_identity(prepared, ctx)
    _verify_existing_signatures(prepared, ctx)
    signature_name = _ROLE_TO_SIGNATURE[role]
    signatures = parse_c2sp_signatures(
        prepared.envelope.get("sigs"),
        str(prepared.envelope.get("type")),
        require_complete=False,
    )
    if signature_name in signatures and not replace_existing:
        raise C2spTlogVerificationError(
            f"prepared event already has a {role.value} signature"
        )
    expected_key = _key_for_role(prepared, role, ctx)
    provider_key = key_provider.jwk(expected_key.kid)
    _assert_same_key(provider_key, expected_key, role)
    signature = key_provider.sign_key(expected_key.kid, prepared.signed_bytes)
    sigs_raw = prepared.envelope.get("sigs")
    new_sigs: dict[str, Any] = dict(sigs_raw) if isinstance(sigs_raw, dict) else {}
    new_sigs[signature_name] = {
        "kid": expected_key.kid,
        "sig": b64url_encode(signature),
    }
    new_envelope = dict(prepared.envelope)
    new_envelope["sigs"] = new_sigs
    return _make_prepared(prepared.reference, new_envelope)


def entry_bytes(
    prepared: PreparedC2spTlogEvent,
    context: C2spVerificationContext | None = None,
) -> bytes:
    """Return the complete canonical entry bytes.

    Requires every role in ``required_signatures`` to be present, verifies
    all of them cryptographically, and re-validates the complete entry.
    Does not append.
    """
    _assert_prepared_integrity(prepared)
    signatures = parse_c2sp_signatures(
        prepared.envelope.get("sigs"),
        str(prepared.envelope.get("type")),
        require_complete=True,
    )
    for role in prepared.required_signatures:
        if _ROLE_TO_SIGNATURE[role] not in signatures:
            raise C2spTlogVerificationError(
                f"missing required {role.value} signature"
            )
    _verify_existing_signatures(prepared, context or C2spVerificationContext())
    data = canonical_bytes(prepared.envelope)
    _assert_entry_size(data)
    parse_c2sp_event_entry(
        data,
        C2spEventContext(
            scope=prepared.reference.scope,
            log_origin=prepared.reference.origin,
            stream_id=prepared.reference.stream_id,
            lr=prepared.reference.lr,
        ),
    )
    return data


def write_prepared_event(
    prepared: PreparedC2spTlogEvent,
    *,
    submit: Callable[[bytes, str], int],
    idempotency_key: str,
    validate_chain: Callable[[PreparedC2spTlogEvent], None] | None = None,
    context: C2spVerificationContext | None = None,
) -> LogRef:
    """Validate the complete entry and append it via *submit*.

    ``submit(entry_bytes, idempotency_key)`` appends the exact bytes and
    returns the assigned entry index. Non-genesis events in every scope require a
    ``validate_chain(prepared)`` callback that checks the chain fields against
    authoritative prior stream state.  Returns the final event reference
    ``{lr}@{index}``.
    """
    if not idempotency_key:
        raise C2spTlogVerificationError(
            "safe c2sp-tlog append requires a non-empty idempotency key"
        )
    data = entry_bytes(prepared, context)
    sequence = prepared.envelope.get("seq")
    if sequence != 0:
        if validate_chain is None:
            raise C2spTlogVerificationError(
                "public non-genesis append requires authoritative chain validation"
            )
        validate_chain(prepared)
    index = submit(data, idempotency_key)
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise C2spTlogVerificationError("append returned an invalid entry index")
    return LogRef.parse(f"{prepared.reference.lr}@{index}")


def _reject_bare_fqdn_writer_stream(
    reference: ParsedC2spTlogLr, fqdn: str
) -> None:
    """Reject replacement-unsafe stream IDs on preparation/write paths only."""
    if reference.stream_id == normalize_fqdn(fqdn, agent_fqdn=True):
        raise C2spTlogParseError(
            "c2sp-tlog writers require an identity-instance stream id, not the bare FQDN"
        )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _make_prepared(
    reference: ParsedC2spTlogLr, envelope: dict[str, Any]
) -> PreparedC2spTlogEvent:
    type_ = str(envelope.get("type"))
    parse_c2sp_signatures(envelope.get("sigs"), type_, require_complete=False)
    signed = dict(envelope)
    signed.pop("sigs", None)
    return PreparedC2spTlogEvent(
        reference=reference,
        envelope=envelope,
        signed_bytes=canonical_bytes(signed),
        required_signatures=required_signer_roles(type_),
    )


def _assert_prepared_envelope(
    value: object, reference: ParsedC2spTlogLr
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise C2spTlogParseError("prepared C2SP event must be an object")
    envelope: dict[str, Any] = value
    _validate_public_fields(envelope, C2spEventContext(
        scope=reference.scope, log_origin=reference.origin,
        stream_id=reference.stream_id, lr=reference.lr,
    ))
    if envelope.get("v") != 1 or envelope.get("kind") != "dnsid.lifecycle":
        raise C2spTlogParseError("unsupported C2SP event envelope")
    type_ = envelope.get("type")
    if not isinstance(type_, str):
        raise C2spTlogParseError("prepared C2SP event missing type")
    required_c2sp_signature_names(type_)
    fqdn = envelope.get("fqdn")
    if not isinstance(fqdn, str) or not fqdn:
        raise C2spTlogParseError("prepared C2SP event missing fqdn")
    ts = envelope.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, int) or ts < 0:
        raise C2spTlogParseError("prepared C2SP event has invalid ts")
    _assert_public_chain_shape(envelope)
    if envelope.get("seq") == 0 and type_ not in ("ISSUANCE", "MIGRATION"):
        raise C2spTlogParseError(
            "public seq=0 event must be ISSUANCE or inbound MIGRATION"
        )
    if (
        envelope.get("seq") == 0
        and type_ == "MIGRATION"
        and envelope.get("new_lr") != reference.lr
    ):
        raise C2spTlogParseError(
            "inbound MIGRATION new_lr must match the bound reference"
        )
    parse_c2sp_signatures(envelope.get("sigs"), type_, require_complete=False)
    return envelope


def _prepare_chain(
    event: AnyLogEvent, reference: ParsedC2spTlogLr, chain: C2spChain | None
) -> C2spChain | None:
    from ..models import IssuanceEvent, MigrationEvent

    if isinstance(event, IssuanceEvent):
        if chain is not None and (
            chain.sequence != 0
            or chain.previous_event_id is not None
            or chain.previous_state_hash is not None
        ):
            raise C2spTlogParseError("public ISSUANCE must be an unchained seq=0 event")
        return C2spChain(sequence=0)
    if (
        isinstance(event, MigrationEvent)
        and event.new_log == reference.lr
        and chain is None
    ):
        return C2spChain(sequence=0)
    if chain is None:
        raise C2spTlogParseError(
            "public non-genesis event requires prepared chain metadata"
        )
    return chain


def _assert_public_chain_shape(envelope: dict[str, Any]) -> None:
    seq = envelope.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise C2spTlogParseError("public C2SP event has invalid seq")
    from .event_codec import parse_chain_fields

    parse_chain_fields(envelope)
    prior = ("prev_event_id", "prev_state_hash")
    if seq == 0:
        if any(name in envelope for name in prior):
            raise C2spTlogParseError(
                "public seq=0 event must not contain previous-chain fields"
            )
        return
    for name in prior:
        v = envelope.get(name)
        if not isinstance(v, str) or not v:
            raise C2spTlogParseError(f"public C2SP event missing {name}")


def _verify_existing_signatures(
    prepared: PreparedC2spTlogEvent, context: C2spVerificationContext
) -> None:
    signatures = parse_c2sp_signatures(
        prepared.envelope.get("sigs"),
        str(prepared.envelope.get("type")),
        require_complete=False,
    )
    for name, signature in signatures.items():
        role = _SIGNATURE_TO_ROLE[name]
        key = _key_for_role(prepared, role, context)
        if signature.kid != key.kid:
            raise C2spTlogVerificationError(
                f"{role.value} signature kid does not match the required key"
            )
        try:
            ok = key.verify(prepared.signed_bytes, b64url_decode(signature.sig))
        except Exception:
            ok = False
        if not ok:
            raise C2spTlogVerificationError(
                f"invalid existing {role.value} signature"
            )


def _assert_expected_identity(
    prepared: PreparedC2spTlogEvent, context: C2spVerificationContext
) -> None:
    """Reject a prepared event that authorizes an unexpected identity.

    Check fields that are actually present on the signed envelope. Non-ISSUANCE
    events omit ``gi``; their governance identity must be checked against the
    trusted stream history rather than silently treating this context as proof.
    The ``ek`` pin is enforced separately in :func:`_key_for_role`.
    """
    envelope = prepared.envelope
    event_type = envelope.get("type")
    if context.fqdn is not None and envelope.get("fqdn") != context.fqdn:
        raise C2spTlogVerificationError(
            f"prepared {event_type} fqdn does not match the expected identity"
        )
    if (
        event_type == "MIGRATION"
        and context.new_lr is not None
        and envelope.get("new_lr") != context.new_lr
    ):
        raise C2spTlogVerificationError(
            "prepared MIGRATION new_lr does not match the expected destination"
        )
    if event_type != "ISSUANCE":
        if context.gi is not None:
            raise C2spTlogVerificationError(
                "non-ISSUANCE events do not carry gi; verify the trusted stream history"
            )
        return
    if context.gi is not None and envelope.get("gi") != context.gi:
        raise C2spTlogVerificationError(
            "prepared ISSUANCE gi does not match the expected identity"
        )
    if context.operational_key is not None:
        embedded_ku = _as_jwk(envelope.get("ku"), "ku")
        if embedded_ku.thumbprint() != context.operational_key.thumbprint():
            raise C2spTlogVerificationError(
                "prepared ISSUANCE ku is not the expected operational key"
            )


def _key_for_role(
    prepared: PreparedC2spTlogEvent,
    role: C2spSignerRole,
    context: C2spVerificationContext,
) -> JWK:
    envelope = prepared.envelope
    if role is C2spSignerRole.ENTITY:
        if envelope.get("type") == "ISSUANCE":
            embedded = _as_jwk(envelope.get("ek"), "ek")
            # Pin the embedded ek to the trusted entity key when the caller
            # supplies one, so an issuer cannot substitute its own ek.
            if (
                context.entity_key is not None
                and embedded.thumbprint() != context.entity_key.thumbprint()
            ):
                raise C2spTlogVerificationError(
                    "ISSUANCE ek does not match the trusted entity key"
                )
            return embedded
        if context.entity_key is not None:
            return context.entity_key
        raise C2spTlogVerificationError("Entity signing requires a trusted entity key")
    if role is C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE:
        return _as_jwk(envelope.get("ku"), "ku")
    if role is C2spSignerRole.NEW_OPERATIONAL:
        return _as_jwk(envelope.get("new_ku"), "new_ku")
    if context.previous_operational_key is not None:
        return context.previous_operational_key
    raise C2spTlogVerificationError(
        "PreviousOperational signing requires the trusted previous operational key"
    )


def _assert_same_key(actual: JWK, expected: JWK, role: C2spSignerRole) -> None:
    if (
        actual.kid != expected.kid
        or actual.alg != expected.alg
        or actual.thumbprint() != expected.thumbprint()
    ):
        raise C2spTlogVerificationError(
            f"{role.value} key provider does not match the prepared event"
        )


def _as_jwk(value: object, name: str) -> JWK:
    from .._crypto import jwk_from_dict

    if not isinstance(value, dict):
        raise C2spTlogParseError(f"prepared C2SP event missing {name}")
    kty, kid, alg = value.get("kty"), value.get("kid"), value.get("alg")
    if (
        not isinstance(kty, str)
        or not isinstance(kid, str)
        or not kid
        or not isinstance(alg, str)
        or not alg
    ):
        raise C2spTlogParseError(f"prepared C2SP event has malformed {name}")
    return jwk_from_dict(value)


def _bound_reference(lr: str) -> ParsedC2spTlogLr:
    parsed = parse_c2sp_tlog_lr(lr)
    if parsed.entry_index is not None:
        raise C2spTlogParseError("prepared events require a bound reference without @index")
    return parsed


def _assert_prepared_integrity(prepared: PreparedC2spTlogEvent) -> None:
    signed = dict(prepared.envelope)
    signed.pop("sigs", None)
    if canonical_bytes(signed) != prepared.signed_bytes:
        raise C2spTlogVerificationError(
            "prepared signed bytes do not match the envelope"
        )
    _assert_prepared_envelope(prepared.envelope, prepared.reference)


def _assert_entry_size(data: bytes) -> None:
    if len(data) == 0 or len(data) > 0xFFFF:
        raise C2spTlogParseError("C2SP entry must be between 1 and 65535 bytes")
