"""Lifecycle verification over a scanned C2SP stream.

Given every entry of a stream, selects the entries that form a valid signed
lifecycle for one domain: an ISSUANCE (or verified MIGRATION genesis)
establishing the entity and operational keys, followed by rotations and
entity-signed lifecycle events, with logical-event chaining in every scope.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

from .._utils import b64url_decode, b64url_encode
from .._verification_budget import remaining_seconds, verification_operation
from ..exceptions import VerificationError
from ..models import (
    JWK,
    AnyLogEvent,
    IssuanceEvent,
    KeyRotationEvent,
    MigrationEvent,
    RetirementEvent,
    RevocationEvent,
)
from .canonical import canonical_bytes, parse_json_no_duplicate_members
from .errors import C2spLifecycleErrorCategory, C2spTlogVerificationError
from .event_codec import (
    C2spEventContext,
    _validate_public_fields,
    c2sp_event_id,
    parse_c2sp_event_entry,
    parse_chain_fields,
    signed_c2sp_entry_bytes,
)
from .merkle import leaf_hash, sha256
from .stream_source import IndexedEntry


@dataclass
class VerifiedLifecycleEvent:
    """One accepted lifecycle entry with its log position and hashes."""

    index: int
    leaf_hash: bytes
    data: bytes
    event: AnyLogEvent
    chain: dict[str, int | str]
    post_keys: tuple[JWK, JWK] | None = None

    @property
    def event_id(self) -> str:
        """Signature-independent identity of this applied payload."""
        return c2sp_event_id(self.data)


@dataclass
class MigrationVerificationResult:
    """Prior state for the advanced low-level lifecycle-selection callback.

    Standard readers do not accept caller-constructed migration results; they
    recover this state through bounded recursive log verification.
    """

    entity_key: JWK
    operational_key: JWK
    prior_events: list[AnyLogEvent] = field(default_factory=list)
    prior_event_refs: list[str] = field(default_factory=list)


@dataclass
class StreamVerifierOptions:
    """Options for advanced lifecycle selection over already proven entries."""

    context: C2spEventContext | None = None
    unchained: bool = False
    signer_key: JWK | None = None
    checkpoint_integration_time_ms: float | None = None
    verify_migration: Callable[[MigrationEvent], MigrationVerificationResult] | None = None
    cutoff_index: int | None = None
    max_entries: int = 100_000
    max_entry_bytes: int = 64 * 1024 * 1024


@verification_operation
def verify_stream_lifecycle(
    entries: list[IndexedEntry],
    domain: str,
    options: StreamVerifierOptions | None = None,
) -> list[VerifiedLifecycleEvent]:
    """Select and verify the lifecycle entries for *domain* from a full scan.

    New payloads require every signer role under their verified predecessor's
    historical state. Applied logical IDs deduplicate regardless of signatures
    or physical position. Authenticated forks or invalid transitions are fatal.
    """
    opts = options or StreamVerifierOptions()
    if (type(opts.max_entries) is not int or opts.max_entries <= 0
            or type(opts.max_entry_bytes) is not int or opts.max_entry_bytes <= 0):
        raise C2spTlogVerificationError("lifecycle limits must be positive integers")
    if len(entries) > opts.max_entries or sum(len(e.data) for e in entries) > opts.max_entry_bytes:
        raise C2spTlogVerificationError("lifecycle input limit exceeded")
    migration_results: dict[int, MigrationVerificationResult] = {}
    if opts.verify_migration is not None:
        verify_migration = opts.verify_migration

        def memoized_migration(event: MigrationEvent) -> MigrationVerificationResult:
            cached = migration_results.get(id(event))
            if cached is not None:
                return cached
            result = verify_migration(event)
            migration_results[id(event)] = result
            return result

        opts = replace(opts, verify_migration=memoized_migration)
    selected: list[VerifiedLifecycleEvent] = []
    applied: dict[str, VerifiedLifecycleEvent] = {}
    for entry in sorted(entries, key=lambda e: e.index):
        remaining_seconds()
        try:
            obj = parse_json_no_duplicate_members(entry.data)
            _validate_public_fields(obj, opts.context or C2spEventContext())
            signed = signed_c2sp_entry_bytes(entry.data)
            identifier = c2sp_event_id(entry.data)
        except Exception:
            continue
        if obj.get("fqdn") != domain:
            continue
        previous_copy = applied.get(identifier)
        if previous_copy is not None:
            if signed_c2sp_entry_bytes(previous_copy.data) != signed:
                raise C2spTlogVerificationError("logical event ID collision")
            continue
        try:
            event = parse_c2sp_event_entry(entry.data, opts.context, candidate=True)
        except Exception as exc:
            if _malformed_authenticated(entry.data, domain, selected, opts):
                raise C2spTlogVerificationError(
                    "authenticated lifecycle candidate is malformed",
                    category=C2spLifecycleErrorCategory.INVALID_EVIDENCE,
                    failing_candidate_index=entry.index,
                ) from exc
            continue
        if event.domain != domain:
            continue
        chain_error: Exception | None = None
        try:
            chain = parse_chain_fields(parse_json_no_duplicate_members(entry.data))
        except Exception as exc:
            chain = {}
            chain_error = exc
        candidate = VerifiedLifecycleEvent(
            index=entry.index,
            leaf_hash=leaf_hash(entry.data),
            data=entry.data,
            event=event,
            chain=chain,
        )
        if not selected and not isinstance(event, (IssuanceEvent, MigrationEvent)):
            continue
        if not selected and isinstance(event, MigrationEvent) and opts.verify_migration is None:
            raise C2spTlogVerificationError(
                "MIGRATION requires verified prior-log history",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
                failing_candidate_index=entry.index,
            )
        try:
            raw = parse_json_no_duplicate_members(entry.data)
            predecessor = applied.get(str(raw.get("prev_event_id", "")))
            authority = selected
            if predecessor is not None:
                authority = selected[:selected.index(predecessor) + 1]
            authenticated = _candidate_is_authenticated(candidate, authority, opts)
        except Exception as exc:
            if not selected and isinstance(event, MigrationEvent):
                raise C2spTlogVerificationError(
                    f"MIGRATION prior-log history could not be verified: {exc}",
                    category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
                    failing_candidate_index=entry.index,
                ) from exc
            authenticated = False
        if not authenticated:
            continue
        if chain_error is not None:
            raise C2spTlogVerificationError(
                "authenticated lifecycle candidate has invalid chain fields",
                category=C2spLifecycleErrorCategory.CHAIN_CONTINUITY,
                failing_candidate_index=entry.index,
            ) from chain_error
        if selected and isinstance(event, IssuanceEvent):
            raise C2spTlogVerificationError(
                "authenticated duplicate ISSUANCE event",
                category=C2spLifecycleErrorCategory.DUPLICATE_ISSUANCE,
                failing_candidate_index=entry.index,
            )
        try:
            # ponytail: O(n²) prefix verification; incremental reducer if throughput matters.
            verify_lifecycle([*selected, candidate], opts)
        except Exception as exc:
            raise C2spTlogVerificationError(
                "authenticated lifecycle candidate is invalid",
                category=_authenticated_failure_category(exc, event),
                failing_candidate_index=entry.index,
            ) from exc
        selected.append(candidate)
        candidate.post_keys = _applied_keys(selected, opts)
        applied[candidate.event_id] = candidate
    verify_lifecycle(selected, opts)
    if opts.cutoff_index is not None:
        cutoff_entry = next((e for e in entries if e.index == opts.cutoff_index), None)
        if cutoff_entry is None:
            raise C2spTlogVerificationError("missing exact migration cutoff occurrence")
        occurrence = verify_occurrence(cutoff_entry, selected, opts)
        if occurrence.event_id != selected[-1].event_id:
            raise C2spTlogVerificationError("cutoff does not identify final logical event")
        selected[-1] = replace(selected[-1], index=cutoff_entry.index, data=cutoff_entry.data,
                               leaf_hash=occurrence.leaf_hash)
    return selected


def verify_occurrence(
    entry: IndexedEntry, selected: list[VerifiedLifecycleEvent], options: StreamVerifierOptions,
) -> VerifiedLifecycleEvent:
    """Authenticate an exact physical copy under its historical signer authority."""
    event = parse_c2sp_event_entry(entry.data, options.context)
    item = VerifiedLifecycleEvent(entry.index, leaf_hash(entry.data), entry.data, event,
                                  parse_chain_fields(parse_json_no_duplicate_members(entry.data)))
    original = next((v for v in selected if v.event_id == item.event_id), None)
    if (original is None
            or signed_c2sp_entry_bytes(original.data) != signed_c2sp_entry_bytes(item.data)):
        raise C2spTlogVerificationError("occurrence is not in the verified lifecycle")
    authority = selected[:selected.index(original)]
    if not authority and isinstance(event, MigrationEvent) and original.post_keys is not None:
        entity, operational = original.post_keys
        options = replace(options, verify_migration=lambda _: MigrationVerificationResult(
            entity, operational
        ))
    if not _candidate_is_authenticated(item, authority, options):
        raise C2spTlogVerificationError("invalid signed occurrence")
    return item


def _malformed_authenticated(
    data: bytes, domain: str, selected: list[VerifiedLifecycleEvent],
    options: StreamVerifierOptions,
) -> bool:
    from .._crypto import jwk_from_dict
    from .event_codec import _validate_public_fields, parse_c2sp_signatures
    try:
        obj = parse_json_no_duplicate_members(data)
        signed = signed_c2sp_entry_bytes(data)
        _validate_public_fields(obj, options.context or C2spEventContext())
        if obj.get("fqdn") != domain or obj.get("v") != 1 or obj.get("kind") != "dnsid.lifecycle":
            return False
        signatures = parse_c2sp_signatures(obj.get("sigs"), obj.get("type"))
        if not selected:
            if obj.get("type") != "ISSUANCE":
                return False
            entity, operational = jwk_from_dict(obj["ek"]), jwk_from_dict(obj["ku"])
            if options.signer_key and entity.thumbprint() != options.signer_key.thumbprint():
                return False
        else:
            predecessor = next(
                (v for v in selected if v.event_id == obj.get("prev_event_id")), None
            )
            authority = (selected if predecessor is None
                         else selected[:selected.index(predecessor) + 1])
            entity, operational = _applied_keys(authority, options)
        keys = {"ae": entity, "prev_op": operational}
        if "op" in signatures:
            if jwk_from_dict(obj["ek"]).thumbprint() != entity.thumbprint():
                return False
            keys["op"] = jwk_from_dict(obj["ku"])
        if "new_op" in signatures:
            keys["new_op"] = jwk_from_dict(obj["new_ku"])
        return all(sig.kid == keys[role].kid and keys[role].verify(signed, b64url_decode(sig.sig))
                   for role, sig in signatures.items())
    except Exception:
        return False


def _candidate_is_authenticated(
    candidate: VerifiedLifecycleEvent,
    selected: list[VerifiedLifecycleEvent],
    options: StreamVerifierOptions,
) -> bool:
    event = candidate.event
    if not selected and isinstance(event, MigrationEvent):
        assert options.verify_migration is not None
        # A standard reader already has the entity key authenticated by the
        # DNS record. Reject unauthenticated noise before fetching prior logs.
        key = options.signer_key
        migrated = None
        if key is None:
            migrated = options.verify_migration(event)
            key = migrated.entity_key
        if event.signing_kid != key.kid:
            return False
        try:
            _verify_event_signature(
                candidate, event.sig, key, "invalid MIGRATION entity signature"
            )
        except (C2spTlogVerificationError, VerificationError):
            return False
        if migrated is None:
            options.verify_migration(event)
        return True
    try:
        if not selected:
            if isinstance(event, IssuanceEvent):
                if event.entity_key is None or event.operational_key is None:
                    return False
                if event.signing_kid != event.entity_key.kid:
                    return False
                if (
                    options.signer_key is not None
                    and options.signer_key.thumbprint() != event.entity_key.thumbprint()
                ):
                    return False
                _verify_event_signature(
                    candidate, event.sig, event.entity_key, "invalid ISSUANCE entity signature"
                )
                _verify_event_signature(
                    candidate,
                    event.operational_countersig,
                    event.operational_key,
                    "invalid ISSUANCE operational countersignature",
                )
                return True
            return False

        entity_key, operational_key = _applied_keys(selected, options)
        if isinstance(event, IssuanceEvent):
            if event.entity_key is None or event.operational_key is None:
                return False
            if event.entity_key.thumbprint() != entity_key.thumbprint():
                return False
            _verify_event_signature(candidate, event.operational_countersig,
                                    event.operational_key, "invalid ISSUANCE countersignature")
        if isinstance(event, KeyRotationEvent):
            if event.previous_kid != operational_key.kid:
                return False
            _verify_event_signature(
                candidate, event.sig, operational_key, "invalid KEY_ROTATION signature"
            )
            if event.new_public_key is None:
                return False
            _verify_event_signature(candidate, event.new_operational_proof,
                                    event.new_public_key, "invalid KEY_ROTATION proof")
            return True
        if event.signing_kid != entity_key.kid:
            return False
        _verify_event_signature(
            candidate, event.sig, entity_key, "invalid lifecycle entity signature"
        )
        return True
    except C2spTlogVerificationError:
        return False
    except VerificationError:
        return False


def _applied_keys(
    selected: list[VerifiedLifecycleEvent], options: StreamVerifierOptions
) -> tuple[JWK, JWK]:
    if selected[-1].post_keys is not None:
        return selected[-1].post_keys
    first = selected[0].event
    if isinstance(first, IssuanceEvent):
        assert first.entity_key is not None and first.operational_key is not None
        entity_key = first.entity_key
        operational_key = first.operational_key
    else:
        assert isinstance(first, MigrationEvent) and options.verify_migration is not None
        migrated = options.verify_migration(first)
        entity_key = migrated.entity_key
        operational_key = migrated.operational_key
    for item in selected[1:]:
        if isinstance(item.event, KeyRotationEvent):
            assert item.event.new_public_key is not None
            operational_key = item.event.new_public_key
    return entity_key, operational_key


def _authenticated_failure_category(
    error: Exception, event: AnyLogEvent
) -> C2spLifecycleErrorCategory | None:
    if isinstance(error, C2spTlogVerificationError) and error.category is not None:
        return error.category
    message = str(error)
    if "seq" in message or "prev_" in message or "public lifecycle event" in message:
        return C2spLifecycleErrorCategory.CHAIN_CONTINUITY
    if isinstance(event, KeyRotationEvent):
        return C2spLifecycleErrorCategory.KEY_CONTINUITY
    if isinstance(event, MigrationEvent):
        return C2spLifecycleErrorCategory.INVALID_MIGRATION
    if "terminal lifecycle" in message:
        return C2spLifecycleErrorCategory.TERMINAL_STATE
    return None


@verification_operation
def verify_lifecycle(
    events: list[VerifiedLifecycleEvent],
    options: StreamVerifierOptions | None = None,
) -> None:
    """Verify that *events* forms one valid, fully signed lifecycle."""
    opts = options or StreamVerifierOptions()
    if not events:
        raise C2spTlogVerificationError("lifecycle contains no ISSUANCE event")
    terminal = False
    prev_state: object = None
    entity_key: JWK | None = None
    operational_key: JWK | None = None
    if opts.unchained:
        raise C2spTlogVerificationError("unchained lifecycle verification is not supported")
    for pos, item in enumerate(events):
        remaining_seconds()
        event = item.event
        if terminal:
            raise C2spTlogVerificationError(
                "event appears after terminal lifecycle event",
                category=C2spLifecycleErrorCategory.TERMINAL_STATE,
            )
        if pos == 0 and not isinstance(event, (IssuanceEvent, MigrationEvent)):
            raise C2spTlogVerificationError(
                "first lifecycle event must be ISSUANCE or verified MIGRATION"
            )
        if pos > 0 and isinstance(event, IssuanceEvent):
            raise C2spTlogVerificationError("duplicate ISSUANCE event")
        if pos > 0 and isinstance(event, MigrationEvent):
            raise C2spTlogVerificationError(
                "MIGRATION is valid only as destination stream genesis",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )
        if opts.checkpoint_integration_time_ms is None:
            raise C2spTlogVerificationError(
                "accepted checkpoint integration time is required"
            )
        if event.timestamp.timestamp() * 1000 > opts.checkpoint_integration_time_ms:
            raise C2spTlogVerificationError(
                "event timestamp is later than checkpoint integration time"
            )
        if pos == 0:
            _assert_first_chain_fields(item)
        else:
            _assert_chain_fields(item, events[pos - 1], prev_state)
        if not event.sig:
            raise C2spTlogVerificationError(f"missing signature for {event.event_type}")
        if isinstance(event, IssuanceEvent):
            _assert_issuance_key_metadata(event)
            assert event.entity_key is not None and event.operational_key is not None
            entity_key = event.entity_key
            operational_key = event.operational_key
            if (
                opts.signer_key is not None
                and opts.signer_key.thumbprint() != entity_key.thumbprint()
            ):
                raise C2spTlogVerificationError(
                    "ISSUANCE entity key does not match trusted entity key"
                )
            _verify_event_signature(
                item, event.sig, entity_key, "invalid ISSUANCE entity signature"
            )
            if not event.operational_countersig:
                raise C2spTlogVerificationError(
                    "ISSUANCE missing operational countersignature"
                )
            _verify_event_signature(
                item,
                event.operational_countersig,
                operational_key,
                "invalid ISSUANCE operational countersignature",
            )
            prev_state = _active_state(event.domain, entity_key, operational_key)
        elif isinstance(event, MigrationEvent) and pos == 0:
            if not event.previous_log or event.previous_log == event.new_log:
                raise C2spTlogVerificationError(
                    "MIGRATION must hand off from a different previous log",
                    category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
                )
            if opts.verify_migration is None:
                raise C2spTlogVerificationError("MIGRATION requires verified prior-log history")
            lr = opts.context.lr if opts.context else None
            if lr and event.new_log != lr:
                raise C2spTlogVerificationError(
                    "MIGRATION new_lr does not match the current C2SP stream"
                )
            migrated = opts.verify_migration(event)
            entity_key = migrated.entity_key
            operational_key = migrated.operational_key
            if entity_key.thumbprint() == operational_key.thumbprint():
                raise C2spTlogVerificationError(
                    "entity and operational keys must be distinct by "
                    "RFC 7638 thumbprint"
                )
            if (
                opts.signer_key is not None
                and opts.signer_key.thumbprint() != entity_key.thumbprint()
            ):
                raise C2spTlogVerificationError(
                    "MIGRATION entity key does not match trusted entity key"
                )
            if event.signing_kid != entity_key.kid:
                raise C2spTlogVerificationError(
                    "MIGRATION signature kid does not match entity key"
                )
            _verify_event_signature(
                item, event.sig, entity_key, "invalid MIGRATION entity signature"
            )
            prev_state = _active_state(event.domain, entity_key, operational_key)
        else:
            if entity_key is None or operational_key is None:
                raise C2spTlogVerificationError(
                    "lifecycle keys were not established by ISSUANCE"
                )
            if isinstance(event, KeyRotationEvent):
                if (
                    event.previous_thumbprint != operational_key.thumbprint()
                    or event.previous_kid != operational_key.kid
                ):
                    raise C2spTlogVerificationError(
                        "KEY_ROTATION previous operational key does not match active key"
                    )
                _assert_rotation_key_metadata(event)
                assert event.new_public_key is not None
                if event.new_public_key.thumbprint() == operational_key.thumbprint():
                    raise C2spTlogVerificationError(
                        "KEY_ROTATION new operational key must differ from active key"
                    )
                if event.new_public_key.thumbprint() == entity_key.thumbprint():
                    raise C2spTlogVerificationError(
                        "entity and operational keys must be distinct by "
                        "RFC 7638 thumbprint"
                    )
                _verify_event_signature(
                    item, event.sig, operational_key, "invalid KEY_ROTATION signature"
                )
                if not event.new_operational_proof:
                    raise C2spTlogVerificationError(
                        "KEY_ROTATION missing new operational proof of possession"
                    )
                _verify_event_signature(
                    item,
                    event.new_operational_proof,
                    event.new_public_key,
                    "invalid KEY_ROTATION new-key proof of possession",
                )
                operational_key = event.new_public_key
            else:
                if isinstance(event, MigrationEvent) and (
                    not event.previous_log or event.previous_log == event.new_log
                ):
                    raise C2spTlogVerificationError(
                        "MIGRATION must hand off to a different log",
                        category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
                    )
                if event.signing_kid != entity_key.kid:
                    raise C2spTlogVerificationError(
                        f"{event.event_type} signature kid does not match entity key"
                    )
                _verify_event_signature(
                    item,
                    event.sig,
                    entity_key,
                    f"invalid {event.event_type} entity signature",
                )
                if isinstance(event, RevocationEvent) and event.reason not in {
                    "keyCompromise", "policyViolation", "superseded", "cessationOfOperation"
                }:
                    raise C2spTlogVerificationError("invalid REVOCATION reason")
            prev_state = _next_state(prev_state, event, entity_key, operational_key)
        if isinstance(event, (RevocationEvent, RetirementEvent)):
            terminal = True


def verify_logged_event_signature(item: VerifiedLifecycleEvent, signer_key: JWK) -> None:
    """Verify one logged event's primary signature against *signer_key*."""
    if not item.event.sig:
        raise C2spTlogVerificationError(f"missing signature for {item.event.event_type}")
    _verify_event_signature(
        item, item.event.sig, signer_key, "invalid lifecycle event signature"
    )


def state_hash(state: object) -> str:
    """Hash of the post-event lifecycle state, used by prev_state_hash chaining."""
    return b64url_encode(sha256(b"dnsid-c2sp-state-v1", canonical_bytes(state)))


def _verify_event_signature(
    item: VerifiedLifecycleEvent, signature: str, key: JWK, message: str
) -> None:
    from ..enums import VerificationCode
    from ..exceptions import VerificationError

    try:
        sig_bytes = b64url_decode(signature)
        ok = key.verify(signed_c2sp_entry_bytes(item.data), sig_bytes)
    except Exception:
        ok = False
    if not ok:
        raise VerificationError(VerificationCode.SIGNATURE_INVALID, message)


def _assert_issuance_key_metadata(event: IssuanceEvent) -> None:
    if event.entity_key is None or event.operational_key is None:
        raise C2spTlogVerificationError("ISSUANCE is missing c2sp-tlog key metadata")
    if not event.entity_key.kid or not event.operational_key.kid:
        raise C2spTlogVerificationError("ISSUANCE is missing c2sp-tlog key metadata")
    if event.entity_key.thumbprint() == event.operational_key.thumbprint():
        raise C2spTlogVerificationError(
            "entity and operational keys must be distinct by RFC 7638 thumbprint"
        )


def _assert_rotation_key_metadata(event: KeyRotationEvent) -> None:
    if event.new_public_key is None or not event.new_thumbprint:
        raise C2spTlogVerificationError("KEY_ROTATION is missing c2sp-tlog key metadata")
    if event.new_thumbprint != event.new_public_key.thumbprint():
        raise C2spTlogVerificationError(
            "KEY_ROTATION new thumbprint does not match public key"
        )
    if event.new_kid != event.new_public_key.kid:
        raise C2spTlogVerificationError("KEY_ROTATION new key metadata mismatch")


def _assert_chain_fields(
    item: VerifiedLifecycleEvent, prev: VerifiedLifecycleEvent, prev_state: object
) -> None:
    prev_seq = prev.chain.get("seq")
    if not isinstance(prev_seq, int) or item.chain.get("seq") != prev_seq + 1:
        raise C2spTlogVerificationError("invalid seq")
    if item.chain.get("prev_event_id") != prev.event_id:
        raise C2spTlogVerificationError("invalid prev_event_id")
    if item.chain.get("prev_state_hash") != state_hash(prev_state):
        raise C2spTlogVerificationError("invalid prev_state_hash")


def _assert_first_chain_fields(item: VerifiedLifecycleEvent) -> None:
    if item.chain.get("seq") != 0:
        raise C2spTlogVerificationError("first public lifecycle event must have seq 0")
    if any(
        name in item.chain
        for name in ("prev_event_id", "prev_state_hash")
    ):
        raise C2spTlogVerificationError(
            "first public lifecycle event must not contain previous-chain fields"
        )


def _active_state(domain: str, entity_key: JWK, operational_key: JWK) -> dict[str, Any]:
    return {
        "fqdn": domain,
        "status": "ACTIVE",
        "entity_thumb": entity_key.thumbprint(),
        "operational_thumb": operational_key.thumbprint(),
    }


def _next_state(
    previous: object, event: AnyLogEvent, entity_key: JWK, operational_key: JWK
) -> object:
    from ..models import DelegationEvent

    if isinstance(event, DelegationEvent):
        return previous
    state = _active_state(event.domain, entity_key, operational_key)
    if isinstance(event, RevocationEvent):
        state["status"] = "REVOKED"
    if isinstance(event, RetirementEvent):
        state["status"] = "RETIRED"
    return state
