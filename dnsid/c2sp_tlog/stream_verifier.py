"""Lifecycle verification over a scanned C2SP stream.

Given every entry of a stream, selects the entries that form a valid signed
lifecycle for one domain: an ISSUANCE (or verified MIGRATION genesis)
establishing the entity and operational keys, followed by rotations and
entity-signed lifecycle events, with logical-event chaining in every scope.

A reader that trusts an entity key (the DNS record's ``ek``) anchors selection
on the entity key current at the *end* of the selected history: genesis
candidates are replayed in log order and the first whose history ends with
that key is accepted.  Without ENTITY_KEY_ROTATION this selects exactly the
genesis whose own entity key is the trusted key.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from dataclasses import dataclass, field, replace
from typing import Any

from .._utils import b64url_decode, b64url_encode
from .._verification_budget import remaining_seconds, verification_operation
from ..exceptions import VerificationError
from ..models import (
    JWK,
    AnyLogEvent,
    EntityKeyRotationEvent,
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

    *entity_key* is the entity key current at the end of the verified prior
    history (the prior ISSUANCE key unless an ENTITY_KEY_ROTATION replaced
    it); it must sign the inbound MIGRATION.  Standard readers do not accept
    caller-constructed migration results; they recover this state through
    bounded recursive log verification.
    """

    entity_key: JWK
    operational_key: JWK
    prior_events: list[AnyLogEvent] = field(default_factory=list)
    prior_event_refs: list[str] = field(default_factory=list)


@dataclass
class StreamVerifierOptions:
    """Options for advanced lifecycle selection over already proven entries.

    *signer_key* is the trusted entity key (the record's ``ek``): the selected
    lifecycle must end with it as the current entity key.
    """

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
    from ._async import run_verification

    return run_verification(
        _verify_stream_lifecycle_steps(entries, domain, options),
        options.verify_migration if options is not None else None,
    )


def _verify_stream_lifecycle_steps(
    entries: list[IndexedEntry],
    domain: str,
    options: StreamVerifierOptions | None = None,
    *,
    migration_results: dict[int, MigrationVerificationResult] | None = None,
    migration_entries: dict[int, bytes] | None = None,
    anchor: _EntityKeyAnchor | None = None,
) -> Generator[MigrationEvent, MigrationVerificationResult, list[VerifiedLifecycleEvent]]:
    """Pause only for authenticated predecessor reads; all validation is shared.

    *migration_entries* receives the exact entry bytes of every MIGRATION
    genesis handed to the predecessor resolver, keyed like
    *migration_results*.  *anchor* overrides ``options.signer_key`` as the
    end-of-history entity key the selected lifecycle must reach.
    """
    opts = options or StreamVerifierOptions()
    if (type(opts.max_entries) is not int or opts.max_entries <= 0
            or type(opts.max_entry_bytes) is not int or opts.max_entry_bytes <= 0):
        raise C2spTlogVerificationError("lifecycle limits must be positive integers")
    if len(entries) > opts.max_entries or sum(len(e.data) for e in entries) > opts.max_entry_bytes:
        raise C2spTlogVerificationError("lifecycle input limit exceeded")
    if migration_results is None:
        migration_results = {}
    if migration_entries is None:
        migration_entries = {}
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
    if anchor is None and opts.signer_key is not None:
        anchor = _EntityKeyAnchor(key=opts.signer_key)
    parsed = _parse_candidates(entries, domain, opts)
    if anchor is None:
        selected = yield from _select_lifecycle(
            parsed, domain, opts, None, None, migration_results, migration_entries,
        )
    else:
        selected = yield from _select_anchored(
            parsed, domain, opts, anchor, migration_results, migration_entries,
        )
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


@dataclass(frozen=True, eq=False)
class _EntityKeyAnchor:
    """The entity key a selected lifecycle must hold at the end of its history.

    Either an exact trusted key (the record's ``ek``), or, for a predecessor
    log behind a MIGRATION, "the key that produced this MIGRATION's ``ae``
    signature" (kid plus signature over the MIGRATION's signed bytes).
    """

    key: JWK | None = None
    kid: str = ""
    signed_bytes: bytes = b""
    sig: str = ""

    @classmethod
    def for_migration_entry(cls, data: bytes) -> _EntityKeyAnchor:
        """Anchor a predecessor history on the signer of a MIGRATION entry."""
        try:
            obj = parse_json_no_duplicate_members(data)
            signed = signed_c2sp_entry_bytes(data)
            sigs = obj.get("sigs") if isinstance(obj, dict) else None
            ae = sigs.get("ae") if isinstance(sigs, dict) else None
            kid = ae.get("kid") if isinstance(ae, dict) else None
            sig = ae.get("sig") if isinstance(ae, dict) else None
        except Exception as exc:
            raise C2spTlogVerificationError(
                "MIGRATION entry is malformed",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            ) from exc
        if not isinstance(kid, str) or not kid or not isinstance(sig, str) or not sig:
            raise C2spTlogVerificationError(
                "MIGRATION entry is missing its entity signature",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )
        return cls(kid=kid, signed_bytes=signed, sig=sig)

    def matches(self, key: JWK | None) -> bool:
        """Return whether *key* satisfies this anchor."""
        if key is None:
            return False
        try:
            if self.key is not None:
                return key.thumbprint() == self.key.thumbprint()
            if not self.kid or key.kid != self.kid:
                return False
            return key.verify(self.signed_bytes, b64url_decode(self.sig))
        except Exception:
            return False

    def cache_id(self) -> str:
        """Stable identity for history caches."""
        if self.key is not None:
            return self.key.thumbprint()
        return "migration:" + b64url_encode(
            sha256(self.signed_bytes, self.sig.encode())
        )


@dataclass
class _ParsedCandidate:
    entry: IndexedEntry
    raw: dict[str, Any]
    signed: bytes
    identifier: str
    event: AnyLogEvent | None
    parse_error: Exception | None
    chain: dict[str, int | str]
    chain_error: Exception | None


def _parse_candidates(
    entries: list[IndexedEntry], domain: str, opts: StreamVerifierOptions,
) -> list[_ParsedCandidate]:
    """Parse every entry for *domain* once; trials reuse the same event objects."""
    parsed: list[_ParsedCandidate] = []
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
        event: AnyLogEvent | None = None
        parse_error: Exception | None = None
        try:
            event = parse_c2sp_event_entry(entry.data, opts.context, candidate=True)
        except Exception as exc:
            parse_error = exc
        chain: dict[str, int | str] = {}
        chain_error: Exception | None = None
        try:
            chain = parse_chain_fields(obj)
        except Exception as exc:
            chain_error = exc
        parsed.append(_ParsedCandidate(
            entry, obj, signed, identifier, event, parse_error, chain, chain_error,
        ))
    return parsed


def _select_anchored(
    parsed: list[_ParsedCandidate],
    domain: str,
    opts: StreamVerifierOptions,
    anchor: _EntityKeyAnchor,
    migration_results: dict[int, MigrationVerificationResult],
    migration_entries: dict[int, bytes],
) -> Generator[MigrationEvent, MigrationVerificationResult, list[VerifiedLifecycleEvent]]:
    """Accept the first genesis whose replayed history ends with the anchor key.

    The first eligible genesis that authenticates decides: if its history ends
    with a different entity key, the anchor is stale and selection fails.

    A genesis is tried only when it could end at the anchor: its own entity
    key satisfies the anchor (for a MIGRATION, it is signed by the anchor
    key), or it is the chain root of an ENTITY_KEY_ROTATION whose new key
    satisfies the anchor and proved possession of it.  Any other genesis is
    noise and is skipped unexamined, exactly as a pinned genesis filter skips
    it; an attacker can only reach the anchor by signing ``new_ae`` with it.
    """
    trial_opts = replace(opts, signer_key=None)
    roots = _anchor_rotation_roots(parsed, anchor)
    chain_thumbprints, migration_root_signers = _anchor_chain_keys(parsed, anchor)

    def genesis_entity_ok(key: JWK) -> bool:
        """Entity keys of the eligible chain make a malformed genesis fatal.

        They are the record key, every key an anchor-reaching rotation chain
        installed or rotated away from (its ISSUANCE root included), and the
        key that signed a MIGRATION root. Unrelated keys stay noise.
        """
        if anchor.matches(key):
            return True
        try:
            if key.thumbprint() in chain_thumbprints:
                return True
        except Exception:
            return False
        return any(signer.matches(key) for signer in migration_root_signers)

    def eligible(item: _ParsedCandidate) -> bool:
        event = item.event
        if event is None or not isinstance(event, (IssuanceEvent, MigrationEvent)):
            return False
        if isinstance(event, IssuanceEvent):
            # Only a self-authenticated ISSUANCE is worth a replay; this keeps
            # forged candidates from multiplying the selection work.
            if not (item.identifier in roots or anchor.matches(event.entity_key)):
                return False
            return _candidate_is_authenticated(_as_candidate(item), [], trial_opts)
        if item.identifier in roots:
            return True
        if anchor.key is not None:
            return _migration_signed_by(_as_candidate(item), anchor.key)
        return bool(anchor.kid) and event.signing_kid == anchor.kid

    # One candidate per logical genesis: a later byte copy of an event is the
    # same event, never a second, shorter history.
    candidates: list[int] = []
    seen_genesis: set[str] = set()
    for item in parsed:
        if item.identifier in seen_genesis or not eligible(item):
            continue
        seen_genesis.add(item.identifier)
        candidates.append(item.entry.index)
    # With no candidate, one pass still applies the malformed-genesis checks.
    for genesis in candidates or [-1]:
        selected = yield from _select_lifecycle(
            parsed, domain, trial_opts, genesis, genesis_entity_ok,
            migration_results, migration_entries,
        )
        if not selected:
            continue
        post_keys = selected[-1].post_keys
        if post_keys is not None and anchor.matches(post_keys[0]):
            return selected
        # An eligible genesis authenticated by the anchor key whose history
        # moved to another entity key is this identity's history: a stale
        # anchor must not fall back to a later, shorter one (for example a
        # fresh genesis by a superseded key, which would drop later events).
        raise C2spTlogVerificationError(
            f"c2sp-tlog current entity key does not match record ek for {domain}"
        )
    return []


def _anchor_rotation_roots(
    parsed: list[_ParsedCandidate], anchor: _EntityKeyAnchor,
) -> set[str]:
    """Chain roots of ENTITY_KEY_ROTATIONs that prove possession of an anchor key."""
    by_id: dict[str, _ParsedCandidate] = {}
    for item in parsed:
        if item.event is not None:
            by_id.setdefault(item.identifier, item)
    resolved: dict[str, str | None] = {}

    def root_of(item: _ParsedCandidate) -> str | None:
        path: list[str] = []
        current = item
        root: str | None
        while True:
            if current.identifier in resolved:
                root = resolved[current.identifier]
                break
            if current.identifier in path:
                root = None
                break
            path.append(current.identifier)
            previous = current.chain.get("prev_event_id")
            if not isinstance(previous, str) or not previous:
                root = current.identifier
                break
            predecessor = by_id.get(previous)
            if predecessor is None:
                root = None
                break
            current = predecessor
        for identifier in path:
            resolved[identifier] = root
        return root

    roots: set[str] = set()
    for item in parsed:
        remaining_seconds()
        event = item.event
        if not isinstance(event, EntityKeyRotationEvent):
            continue
        new_key = event.new_entity_public_key
        if new_key is None or not anchor.matches(new_key):
            continue
        try:
            proven = bool(event.new_entity_proof) and new_key.verify(
                item.signed, b64url_decode(event.new_entity_proof)
            )
        except Exception:
            proven = False
        if not proven:
            continue
        root = root_of(item)
        if root is not None:
            roots.add(root)
    return roots


def _anchor_chain_keys(
    parsed: list[_ParsedCandidate], anchor: _EntityKeyAnchor,
) -> tuple[set[str], list[_EntityKeyAnchor]]:
    """Entity keys along every anchor-reaching rotation chain.

    Walks back from each ENTITY_KEY_ROTATION that proves possession of an
    anchor key. The path is fixed by hashes inside bytes the anchor key
    signed, so only keys the identity holds or has held are collected:
    every rotated-in key, the ISSUANCE root key, and (as a signature check)
    the signer of a MIGRATION root.
    """
    by_id: dict[str, _ParsedCandidate] = {}
    for item in parsed:
        if item.event is not None:
            by_id.setdefault(item.identifier, item)
    thumbprints: set[str] = set()
    migration_signers: list[_EntityKeyAnchor] = []
    visited: set[str] = set()
    for item in parsed:
        remaining_seconds()
        event = item.event
        if not isinstance(event, EntityKeyRotationEvent):
            continue
        new_key = event.new_entity_public_key
        if new_key is None or not anchor.matches(new_key):
            continue
        try:
            proven = bool(event.new_entity_proof) and new_key.verify(
                item.signed, b64url_decode(event.new_entity_proof)
            )
        except Exception:
            proven = False
        if not proven:
            continue
        current: _ParsedCandidate | None = item
        while current is not None and current.identifier not in visited:
            visited.add(current.identifier)
            step = current.event
            if isinstance(step, EntityKeyRotationEvent) and step.new_entity_public_key:
                thumbprints.add(step.new_entity_public_key.thumbprint())
            previous = current.chain.get("prev_event_id")
            if isinstance(previous, str) and previous:
                current = by_id.get(previous)
                continue
            if isinstance(step, IssuanceEvent) and step.entity_key is not None:
                thumbprints.add(step.entity_key.thumbprint())
            elif isinstance(step, MigrationEvent):
                try:
                    migration_signers.append(
                        _EntityKeyAnchor.for_migration_entry(current.entry.data)
                    )
                except C2spTlogVerificationError:
                    pass
            current = None
    return thumbprints, migration_signers


def _as_candidate(item: _ParsedCandidate) -> VerifiedLifecycleEvent:
    assert item.event is not None
    return VerifiedLifecycleEvent(
        index=item.entry.index,
        leaf_hash=leaf_hash(item.entry.data),
        data=item.entry.data,
        event=item.event,
        chain=item.chain,
    )


def _select_lifecycle(
    parsed: list[_ParsedCandidate],
    domain: str,
    opts: StreamVerifierOptions,
    genesis_index: int | None,
    genesis_entity_ok: Callable[[JWK], bool] | None,
    migration_results: dict[int, MigrationVerificationResult],
    migration_entries: dict[int, bytes],
) -> Generator[MigrationEvent, MigrationVerificationResult, list[VerifiedLifecycleEvent]]:
    """One greedy selection pass; *genesis_index* (when set) is the only genesis."""
    selected: list[VerifiedLifecycleEvent] = []
    applied: dict[str, VerifiedLifecycleEvent] = {}
    for item in parsed:
        remaining_seconds()
        entry = item.entry
        previous_copy = applied.get(item.identifier)
        if previous_copy is not None:
            if signed_c2sp_entry_bytes(previous_copy.data) != item.signed:
                raise C2spTlogVerificationError("logical event ID collision")
            continue
        event = item.event
        if event is None:
            if _malformed_authenticated(entry.data, domain, selected, opts, genesis_entity_ok):
                raise C2spTlogVerificationError(
                    "authenticated lifecycle candidate is malformed",
                    category=C2spLifecycleErrorCategory.INVALID_EVIDENCE,
                    failing_candidate_index=entry.index,
                ) from item.parse_error
            continue
        if event.domain != domain:
            continue
        candidate = _as_candidate(item)
        if not selected and not isinstance(event, (IssuanceEvent, MigrationEvent)):
            continue
        if not selected and isinstance(event, MigrationEvent) and opts.verify_migration is None:
            raise C2spTlogVerificationError(
                "MIGRATION requires verified prior-log history",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
                failing_candidate_index=entry.index,
            )
        if not selected and genesis_index is not None and entry.index != genesis_index:
            continue
        try:
            predecessor = applied.get(str(item.raw.get("prev_event_id", "")))
            authority = selected
            if predecessor is not None:
                authority = selected[:selected.index(predecessor) + 1]
            if (not selected and isinstance(event, MigrationEvent)
                    and id(event) not in migration_results):
                migration_entries[id(event)] = entry.data
                migration_results[id(event)] = yield event
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
        if item.chain_error is not None:
            raise C2spTlogVerificationError(
                "authenticated lifecycle candidate has invalid chain fields",
                category=C2spLifecycleErrorCategory.CHAIN_CONTINUITY,
                failing_candidate_index=entry.index,
            ) from item.chain_error
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
    genesis_entity_ok: Callable[[JWK], bool] | None = None,
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
            if genesis_entity_ok is not None and not genesis_entity_ok(entity):
                return False
        else:
            predecessor = next(
                (v for v in selected if v.event_id == obj.get("prev_event_id")), None
            )
            authority = (selected if predecessor is None
                         else selected[:selected.index(predecessor) + 1])
            entity, operational = _applied_keys(authority, options)
        keys = {"ae": entity, "prev_ae": entity, "prev_op": operational}
        if "op" in signatures:
            if jwk_from_dict(obj["ek"]).thumbprint() != entity.thumbprint():
                return False
            keys["op"] = jwk_from_dict(obj["ku"])
        if "new_op" in signatures:
            keys["new_op"] = jwk_from_dict(obj["new_ku"])
        if "new_ae" in signatures:
            from ..models import _PRIVATE_JWK_MEMBERS

            new_entity = obj["new_ek"]
            # A private new_ek is never used as a verification key: noise.
            if not isinstance(new_entity, dict) or _PRIVATE_JWK_MEMBERS & new_entity.keys():
                return False
            keys["new_ae"] = jwk_from_dict(new_entity)

        # Every role must name its key: a new_ek without a kid, or a new_ae
        # naming another kid, cannot authenticate and is noise.
        return all(
            bool(sig.kid) and sig.kid == keys[role].kid
            and keys[role].verify(signed, b64url_decode(sig.sig))
            for role, sig in signatures.items()
        )
    except Exception:
        return False


def _migration_signed_by(candidate: VerifiedLifecycleEvent, key: JWK) -> bool:
    if candidate.event.signing_kid != key.kid:
        return False
    try:
        _verify_event_signature(
            candidate, candidate.event.sig, key, "invalid MIGRATION entity signature",
        )
    except (C2spTlogVerificationError, VerificationError):
        return False
    return True


def _candidate_is_authenticated(
    candidate: VerifiedLifecycleEvent,
    selected: list[VerifiedLifecycleEvent],
    options: StreamVerifierOptions,
) -> bool:
    event = candidate.event
    if not selected and isinstance(event, MigrationEvent):
        assert options.verify_migration is not None
        # Authorized by the entity key current at the end of the verified
        # prior history. Selection has already filtered unanchored noise
        # before any prior-log read.
        migrated = options.verify_migration(event)
        return _migration_signed_by(candidate, migrated.entity_key)
    try:
        if not selected:
            if isinstance(event, IssuanceEvent):
                if event.entity_key is None or event.operational_key is None:
                    return False
                if event.signing_kid != event.entity_key.kid:
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
        if isinstance(event, EntityKeyRotationEvent):
            # prev_ae authorizes with the entity key current at the predecessor;
            # new_ae proves possession of the key being installed.
            if event.signing_kid != entity_key.kid:
                return False
            _verify_event_signature(
                candidate, event.sig, entity_key, "invalid ENTITY_KEY_ROTATION signature"
            )
            new_key = event.new_entity_public_key
            if new_key is None or event.new_entity_kid != new_key.kid:
                return False
            _verify_event_signature(candidate, event.new_entity_proof, new_key,
                                    "invalid ENTITY_KEY_ROTATION proof")
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
        elif isinstance(item.event, EntityKeyRotationEvent):
            assert item.event.new_entity_public_key is not None
            entity_key = item.event.new_entity_public_key
    return entity_key, operational_key


def _authenticated_failure_category(
    error: Exception, event: AnyLogEvent
) -> C2spLifecycleErrorCategory | None:
    if isinstance(error, C2spTlogVerificationError) and error.category is not None:
        return error.category
    message = str(error)
    if "seq" in message or "prev_" in message or "public lifecycle event" in message:
        return C2spLifecycleErrorCategory.CHAIN_CONTINUITY
    if isinstance(event, (KeyRotationEvent, EntityKeyRotationEvent)):
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
    """Verify that *events* forms one valid, fully signed lifecycle.

    With ``options.signer_key`` set, the entity key current at the end of
    *events* must be that key.
    """
    opts = options or StreamVerifierOptions()
    if not events:
        raise C2spTlogVerificationError("lifecycle contains no ISSUANCE event")
    # Without entity-key rotation the genesis key is the final key, so the
    # trusted-key check keeps its historical genesis-time error.
    rotates_entity = any(isinstance(item.event, EntityKeyRotationEvent) for item in events)
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
                and not rotates_entity
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
                and not rotates_entity
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
            elif isinstance(event, EntityKeyRotationEvent):
                entity_key = _verify_entity_rotation(item, event, entity_key, operational_key)
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
    if (
        opts.signer_key is not None
        and entity_key is not None
        and opts.signer_key.thumbprint() != entity_key.thumbprint()
    ):
        raise C2spTlogVerificationError(
            f"c2sp-tlog current entity key does not match record ek for {events[0].event.domain}"
        )


def _verify_entity_rotation(
    item: VerifiedLifecycleEvent,
    event: EntityKeyRotationEvent,
    entity_key: JWK,
    operational_key: JWK,
) -> JWK:
    """Apply an authenticated ENTITY_KEY_ROTATION; return the new entity key."""
    if event.signing_kid != entity_key.kid:
        raise C2spTlogVerificationError(
            "ENTITY_KEY_ROTATION signature kid does not match entity key"
        )
    _verify_event_signature(
        item, event.sig, entity_key, "invalid ENTITY_KEY_ROTATION previous-entity signature"
    )
    _assert_entity_rotation_key_metadata(event)
    new_key = event.new_entity_public_key
    assert new_key is not None
    if not event.new_entity_proof:
        raise C2spTlogVerificationError(
            "ENTITY_KEY_ROTATION missing new entity proof of possession"
        )
    _verify_event_signature(
        item, event.new_entity_proof, new_key,
        "invalid ENTITY_KEY_ROTATION new-key proof of possession",
    )
    current = entity_key.thumbprint()
    if event.previous_entity_thumbprint != current:
        raise C2spTlogVerificationError(
            "authenticated ENTITY_KEY_ROTATION does not continue from the active entity key",
            category=C2spLifecycleErrorCategory.KEY_CONTINUITY,
        )
    if event.new_entity_thumbprint in (current, operational_key.thumbprint()):
        raise C2spTlogVerificationError(
            "authenticated ENTITY_KEY_ROTATION new key binding is invalid",
            category=C2spLifecycleErrorCategory.KEY_CONTINUITY,
        )
    return new_key


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


def _assert_entity_rotation_key_metadata(event: EntityKeyRotationEvent) -> None:
    key = event.new_entity_public_key
    if key is None or not event.new_entity_thumbprint or not event.previous_entity_thumbprint:
        raise C2spTlogVerificationError(
            "ENTITY_KEY_ROTATION is missing c2sp-tlog key metadata"
        )
    if event.new_entity_thumbprint != key.thumbprint():
        raise C2spTlogVerificationError(
            "ENTITY_KEY_ROTATION new thumbprint does not match public key"
        )
    if event.new_entity_thumbprint == event.previous_entity_thumbprint:
        raise C2spTlogVerificationError(
            "ENTITY_KEY_ROTATION new thumbprint must differ from previous thumbprint"
        )
    if event.new_entity_kid != key.kid:
        raise C2spTlogVerificationError("ENTITY_KEY_ROTATION new key metadata mismatch")


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
