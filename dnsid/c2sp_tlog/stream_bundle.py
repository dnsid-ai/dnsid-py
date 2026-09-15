"""Strict verification of ``dnsid-c2sp-stream-bundle@v1`` evidence."""

from __future__ import annotations

import datetime
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from .._utils import b64url_decode_strict, b64url_encode, normalize_fqdn
from .._verification_budget import verification_operation
from ..models import JWK, IssuanceEvent, KeyRotationEvent, MigrationEvent
from .canonical import (
    _MAX_SAFE_INT,
    assert_canonical_json_bytes,
    canonical_bytes,
    parse_json_no_duplicate_members,
)
from .checkpoint import Checkpoint, parse_checkpoint
from .checkpoint_store import (
    CheckpointStore,
    InMemoryCheckpointStore,
    TrustedCheckpoint,
)
from .errors import (
    C2spCheckpointConsistencyError,
    C2spLifecycleErrorCategory,
    C2spTlogParseError,
    C2spTlogTransportError,
    C2spTlogVerificationError,
)
from .event_codec import C2spEventContext
from .lr import ParsedC2spTlogLr, parse_c2sp_tlog_lr
from .merkle import merkle_root_from_entries, sha256, verify_consistency, verify_inclusion
from .policy import (
    C2spTlogPolicy,
    enforce_checkpoint_policy,
    normalized_origin_policy,
    parse_c2sp_policy_file,
)
from .resource_fetcher import (
    C2spBoundedResourceFetcher,
    C2spResourceFetchGuarantees,
    fetch_bounded_bytes,
)
from .signed_note import SignedNoteKey
from .stream_source import (
    C2spConsistencyProofSource,
    C2spProvenEntry,
    C2spStreamEvidence,
    C2spTlogSource,
    IndexedEntry,
)
from .stream_verifier import (
    MigrationVerificationResult,
    StreamVerifierOptions,
    VerifiedLifecycleEvent,
    verify_stream_lifecycle,
)

_TOP_LEVEL_MEMBERS = frozenset(
    {
        "v",
        "type",
        "fqdn",
        "lr",
        "checkpoint",
        "policy_hash",
        "complete_through_size",
        "completeness_mode",
        "events",
        "state",
        "expires",
        "sig",
    }
)
_EVENT_MEMBERS = frozenset({"index", "entry", "proof"})
_STATE_MEMBERS = frozenset({"event_count", "last_event_type", "logged_state"})
_SIG_MEMBERS = frozenset({"alg", "kid", "value"})


class _MissingC2spConsistencyEvidenceError(C2spTlogVerificationError):
    pass


@dataclass
class C2spStreamBundleVerifierOptions:
    """Local trust and resource limits for portable stream bundle verification.

    ``policy_bytes`` and ``bundle_keys`` are independent trust inputs; neither
    is taken from the bundle. Times and configured lifetime/freshness bounds
    are milliseconds, matching :class:`C2spTlogReaderOptions`.
    """

    policy_bytes: bytes
    bundle_keys: list[SignedNoteKey]
    entity_key: JWK
    checkpoint_freshness_ms: int
    max_bundle_lifetime_ms: int
    max_bundle_bytes: int
    max_events: int
    max_tree_size: int = 1_000_000
    max_clock_skew_ms: int = 0
    consistency_source: C2spConsistencyProofSource | None = None
    checkpoint_store: CheckpointStore = field(default_factory=InMemoryCheckpointStore)
    now: Callable[[], float] = time.time


@dataclass
class VerifiedC2spStreamBundle:
    """A fully verified portable bundle of logged lifecycle state."""

    reference: ParsedC2spTlogLr
    checkpoint: Checkpoint
    events: list[VerifiedLifecycleEvent]
    logged_state: str
    active_operational_thumbprint: str
    expires: int
    bundle_signer_kid: str
    fqdn: str = field(default="", kw_only=True)
    checkpoint_witness_time: datetime.datetime = field(
        default=datetime.datetime.min.replace(tzinfo=datetime.UTC), kw_only=True
    )
    checkpoint_bytes: bytes = field(default=b"", kw_only=True)
    migration_results: dict[int, MigrationVerificationResult] = field(
        default_factory=dict, repr=False, kw_only=True
    )


class _FetchedStreamBundleSource:
    """Fetch verified per-domain bundles, with bounded raw-scan fallback."""

    def __init__(
        self,
        fetcher: C2spBoundedResourceFetcher,
        fallback: C2spTlogSource,
        *,
        policy_bytes: bytes,
        bundle_keys: list[SignedNoteKey],
        checkpoint_freshness_ms: int,
        max_bundle_lifetime_ms: int,
        max_bundle_bytes: int,
        max_events: int,
        max_tree_size: int = 1_000_000,
        max_clock_skew_ms: int = 0,
        checkpoint_store: CheckpointStore | None = None,
        require_bundle: bool = False,
        now: Callable[[], float] = time.time,
    ) -> None:
        """Configure bundle trust, limits, and the complete raw fallback."""
        if type(require_bundle) is not bool:
            raise C2spTlogVerificationError("require_bundle must be a boolean")
        self._fetcher = fetcher
        self._fallback = fallback
        self._policy_bytes = policy_bytes
        self._bundle_keys = bundle_keys
        self._checkpoint_freshness_ms = checkpoint_freshness_ms
        self._max_bundle_lifetime_ms = max_bundle_lifetime_ms
        self._max_bundle_bytes = max_bundle_bytes
        self._max_events = max_events
        self._max_tree_size = max_tree_size
        self._max_clock_skew_ms = max_clock_skew_ms
        self._checkpoint_store = (
            checkpoint_store
            if checkpoint_store is not None
            else InMemoryCheckpointStore()
        )
        self._require_bundle = require_bundle
        self._now = now

    def load_verified_bundle(
        self,
        reference: ParsedC2spTlogLr,
        fqdn: str,
        entity_key: JWK,
        verify_migration: Callable[[MigrationEvent], MigrationVerificationResult] | None,
        *,
        cutoff_index: int | None = None,
        account_response: Callable[[int], None] | None = None,
    ) -> VerifiedC2spStreamBundle | None:
        """Fetch and verify the bundle bound to the authenticated reference."""
        normalized = normalize_fqdn(fqdn, agent_fqdn=True)
        endpoint = (
            f"{reference.log_prefix}/streams/{quote(normalized, safe='')}?format=bundle"
        )
        try:
            data = fetch_bounded_bytes(self._fetcher, endpoint, self._max_bundle_bytes)
        except C2spTlogTransportError as exc:
            if not self._require_bundle and _bundle_fallback_allowed(exc):
                return None
            raise
        if account_response is not None:
            account_response(len(data))
        options = C2spStreamBundleVerifierOptions(
            policy_bytes=self._policy_bytes,
            bundle_keys=self._bundle_keys,
            entity_key=entity_key,
            checkpoint_freshness_ms=self._checkpoint_freshness_ms,
            max_bundle_lifetime_ms=self._max_bundle_lifetime_ms,
            max_bundle_bytes=self._max_bundle_bytes,
            max_events=self._max_events,
            max_tree_size=self._max_tree_size,
            max_clock_skew_ms=self._max_clock_skew_ms,
            checkpoint_store=InMemoryCheckpointStore(),
            now=self._now,
        )
        verified = _verify_c2sp_stream_bundle(
            data, options, verify_migration, cutoff_index, reference.lr
        )
        if verified.fqdn != normalized:
            raise C2spTlogVerificationError(
                "stream bundle fqdn does not match requested domain"
            )
        options.checkpoint_store = self._checkpoint_store
        try:
            _verify_and_advance_checkpoint(
                verified.reference,
                verified.checkpoint,
                verified.checkpoint_witness_time,
                options,
            )
        except _MissingC2spConsistencyEvidenceError:
            if self._require_bundle:
                raise
            evidence = self._fallback.load_stream(reference, fqdn)
            if account_response is not None:
                account_response(_stream_evidence_bytes(evidence))
            complete_entries = _verified_complete_scan_entries(evidence)
            _verify_and_advance_checkpoint(
                verified.reference,
                verified.checkpoint,
                verified.checkpoint_witness_time,
                options,
                complete_entries=complete_entries,
            )
        return verified

    def fetch_checkpoint(self, reference: ParsedC2spTlogLr) -> bytes:
        """Use raw standard resources for single-event reads."""
        return self._fallback.fetch_checkpoint(reference)

    def read_entry(
        self, reference: ParsedC2spTlogLr, index: int
    ) -> C2spProvenEntry:
        """Use raw discovery for a single entry."""
        return self._fallback.read_entry(reference, index)

    def load_stream(
        self, reference: ParsedC2spTlogLr, fqdn: str
    ) -> C2spStreamEvidence:
        """Load the bounded raw fallback selected by the reader."""
        return self._fallback.load_stream(reference, fqdn)

    def security_guarantees(self) -> C2spResourceFetchGuarantees | None:
        """Expose the shared fetcher's public-read guarantees."""
        value = self._fetcher.security_guarantees()
        return value if isinstance(value, C2spResourceFetchGuarantees) else None


@verification_operation
def verify_c2sp_stream_bundle(
    data: bytes,
    options: C2spStreamBundleVerifierOptions,
) -> VerifiedC2spStreamBundle:
    """Parse and verify one canonical ``dnsid-c2sp-stream-bundle@v1``.

    Successful return establishes logged lifecycle state through the accepted
    checkpoint. It does not establish current protocol status. Migrated bundles
    require reader-managed recursive predecessor resolution and are rejected by
    this standalone verifier. Invalid, expired, incomplete, or incorrectly
    bound evidence fails closed.
    """
    return _verify_c2sp_stream_bundle(data, options, None, None, None)


def _verify_c2sp_stream_bundle(
    data: bytes,
    options: C2spStreamBundleVerifierOptions,
    migration_verifier: Callable[[MigrationEvent], MigrationVerificationResult]
    | None,
    cutoff_index: int | None,
    expected_lr: str | None,
) -> VerifiedC2spStreamBundle:
    _validate_options(options)
    if len(data) > options.max_bundle_bytes:
        raise C2spTlogVerificationError(
            f"stream bundle exceeds configured byte maximum {options.max_bundle_bytes}"
        )
    value = parse_json_no_duplicate_members(data)
    assert_canonical_json_bytes(data, value)
    obj = _exact_object(value, _TOP_LEVEL_MEMBERS, "stream bundle")
    _assert_all_safe_integers(obj)

    if obj["v"] != 1 or obj["type"] != "dnsid-c2sp-stream-bundle":
        raise C2spTlogParseError("unsupported stream bundle type or version")
    fqdn = _string(obj["fqdn"], "fqdn")
    try:
        normalized_fqdn = normalize_fqdn(fqdn, agent_fqdn=True)
    except Exception as exc:
        raise C2spTlogParseError(f"invalid stream bundle fqdn: {exc}") from exc
    if fqdn != normalized_fqdn:
        raise C2spTlogParseError("stream bundle fqdn must be normalized lowercase")

    lr = _string(obj["lr"], "lr")
    reference = parse_c2sp_tlog_lr(lr)
    if lr != reference.lr:
        raise C2spTlogParseError("stream bundle lr must be a canonical bound reference")
    if expected_lr is not None and reference.lr != expected_lr:
        raise C2spTlogVerificationError(
            "stream bundle lr does not match authenticated record"
        )
    raw_events = obj["events"]
    if not isinstance(raw_events, list):
        raise C2spTlogParseError("stream bundle events must be an array")
    if not raw_events:
        raise C2spTlogVerificationError("stream bundle requires events")
    if len(raw_events) > options.max_events:
        raise C2spTlogVerificationError(
            f"stream bundle exceeds configured event maximum {options.max_events}"
        )

    policy = _parse_policy(options.policy_bytes)
    policy_hash = _decode_b64(obj["policy_hash"], "policy_hash")
    if len(policy_hash) != 32 or policy_hash != sha256(options.policy_bytes):
        raise C2spTlogVerificationError("stream bundle policy_hash mismatch")

    checkpoint_bytes = _decode_b64(obj["checkpoint"], "checkpoint")
    try:
        checkpoint = parse_checkpoint(checkpoint_bytes.decode("utf-8", errors="strict"))
    except UnicodeDecodeError as exc:
        raise C2spTlogParseError("stream bundle checkpoint is not UTF-8") from exc
    tree_size = _safe_int(obj["complete_through_size"], "complete_through_size")
    if tree_size != checkpoint.tree_size:
        raise C2spTlogVerificationError("stream bundle checkpoint size mismatch")
    if tree_size > options.max_tree_size:
        raise C2spTlogVerificationError(
            f"stream bundle checkpoint exceeds tree-size maximum {options.max_tree_size}"
        )
    if obj["completeness_mode"] != "trusted-index":
        raise C2spTlogVerificationError("unsupported stream bundle completeness_mode")

    now_ms = options.now() * 1000
    try:
        policy_result = enforce_checkpoint_policy(
            checkpoint,
            reference.origin,
            policy,
            reference.scope,
            now_ms,
            options.max_clock_skew_ms,
        )
    except C2spTlogVerificationError as exc:
        if exc.category is None:
            exc.category = C2spLifecycleErrorCategory.INVALID_EVIDENCE
        raise
    witness_time = policy_result.checkpoint_witness_time
    if witness_time is None:
        raise C2spTlogVerificationError(
            "stream bundle requires an accepted timestamped checkpoint witness quorum",
            category=C2spLifecycleErrorCategory.INVALID_EVIDENCE,
        )
    witness_time_ms = witness_time.timestamp() * 1000
    if now_ms - witness_time_ms > options.checkpoint_freshness_ms:
        raise C2spTlogVerificationError("stream bundle checkpoint is too stale")

    signer_kid = _verify_bundle_signature(obj, options.bundle_keys, policy, reference)
    entries = _parse_and_verify_events(raw_events, checkpoint)
    if cutoff_index is not None:
        entries = [entry for entry in entries if entry.index <= cutoff_index]
    context = C2spEventContext(
        scope=reference.scope,
        log_origin=reference.origin,
        stream_id=reference.stream_id,
        lr=reference.lr,
    )
    migration_results: dict[int, MigrationVerificationResult] = {}

    def verify_migration_memoized(
        event: MigrationEvent,
    ) -> MigrationVerificationResult:
        cached = migration_results.get(id(event))
        if cached is not None:
            return cached
        if migration_verifier is None:
            raise C2spTlogVerificationError(
                "MIGRATION requires verified prior-log history"
            )
        result = migration_verifier(event)
        migration_results[id(event)] = result
        return result

    verified = verify_stream_lifecycle(
        entries,
        fqdn,
        StreamVerifierOptions(
            context=context,
            cutoff_index=cutoff_index,
            unchained=normalized_origin_policy(policy, reference.origin).unchained,
            signer_key=options.entity_key,
            checkpoint_integration_time_ms=(
                witness_time_ms + options.max_clock_skew_ms
            ),
            verify_migration=(
                verify_migration_memoized if migration_verifier is not None else None
            ),
        ),
    )
    if cutoff_index is not None and (
        not verified or verified[-1].index != cutoff_index
    ):
        raise C2spTlogVerificationError(
            "MIGRATION prev_ref does not identify the final applied cutoff event",
            category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
        )
    logged_state = _logged_state(verified)
    state = _exact_object(obj["state"], _STATE_MEMBERS, "stream bundle state")
    expected_state = {
        "event_count": len(verified),
        "last_event_type": str(verified[-1].event.event_type),
        "logged_state": logged_state,
    }
    if cutoff_index is None and state != expected_state:
        raise C2spTlogVerificationError("stream bundle state does not match replay")

    expires = _safe_int(obj["expires"], "expires")
    if expires * 1000 <= now_ms:
        raise C2spTlogVerificationError("stream bundle is expired")
    if expires * 1000 - witness_time_ms > options.max_bundle_lifetime_ms:
        raise C2spTlogVerificationError(
            "stream bundle expiry exceeds configured checkpoint lifetime"
        )
    result = VerifiedC2spStreamBundle(
        reference=reference,
        fqdn=normalized_fqdn,
        checkpoint=checkpoint,
        checkpoint_witness_time=witness_time,
        checkpoint_bytes=checkpoint_bytes,
        events=verified,
        logged_state=logged_state,
        active_operational_thumbprint=_active_operational_thumbprint(
            verified, migration_results
        ),
        expires=expires,
        bundle_signer_kid=signer_kid,
        migration_results=migration_results,
    )
    _verify_and_advance_checkpoint(
        reference, checkpoint, witness_time, options
    )
    return result


def _stream_evidence_bytes(evidence: C2spStreamEvidence) -> int:
    represented = len(evidence.checkpoint_bytes) + sum(
        len(entry.data) + 2 for entry in evidence.entries
    )
    return max(represented, evidence.response_bytes or 0)


def _bundle_fallback_allowed(exc: C2spTlogTransportError) -> bool:
    if exc.status_code is not None:
        return exc.status_code in (404, 408, 429) or exc.status_code >= 500
    return exc.transient


def _validate_options(options: C2spStreamBundleVerifierOptions) -> None:
    for name in ("max_bundle_bytes", "max_events", "max_tree_size"):
        value = getattr(options, name)
        if type(value) is not int or value < 1:
            raise C2spTlogVerificationError(f"{name} must be a positive integer")
    for name in ("checkpoint_freshness_ms", "max_bundle_lifetime_ms"):
        value = getattr(options, name)
        if type(value) is not int or value < 1:
            raise C2spTlogVerificationError(f"{name} must be a positive integer")
    if type(options.max_clock_skew_ms) is not int or options.max_clock_skew_ms < 0:
        raise C2spTlogVerificationError(
            "max_clock_skew_ms must be a non-negative integer"
        )
    if not options.bundle_keys:
        raise C2spTlogVerificationError("stream bundle verifier requires trusted keys")


def _parse_policy(policy_bytes: bytes) -> C2spTlogPolicy:
    try:
        return parse_c2sp_policy_file(policy_bytes.decode("utf-8", errors="strict"))
    except UnicodeDecodeError as exc:
        raise C2spTlogVerificationError("configured policy bytes are not UTF-8") from exc


def _verify_and_advance_checkpoint(
    reference: ParsedC2spTlogLr,
    checkpoint: Checkpoint,
    witness_time: datetime.datetime,
    options: C2spStreamBundleVerifierOptions,
    *,
    complete_entries: list[IndexedEntry] | None = None,
) -> None:
    candidate = TrustedCheckpoint(
        origin=reference.origin,
        tree_size=checkpoint.tree_size,
        root_hash=checkpoint.root_hash,
        witness_time=witness_time,
    )

    entries = sorted(complete_entries or [], key=lambda entry: entry.index)

    def _verify(stored: TrustedCheckpoint | None) -> None:
        if complete_entries is not None:
            _verify_checkpoint_prefix(entries, candidate, "candidate")
        if stored is None:
            return
        if stored.tree_size > candidate.tree_size:
            raise C2spCheckpointConsistencyError(
                "stream bundle checkpoint regressed below trusted size",
                category=C2spLifecycleErrorCategory.LOG_ROLLBACK,
                trusted=stored,
                observed=candidate,
            )
        if stored.tree_size == candidate.tree_size:
            if stored.root_hash != candidate.root_hash:
                raise C2spCheckpointConsistencyError(
                    "stream bundle checkpoint conflicts at trusted size",
                    category=C2spLifecycleErrorCategory.LOG_FORK,
                    trusted=stored,
                    observed=candidate,
                )
            return
        if options.consistency_source is not None:
            proof = options.consistency_source.fetch_consistency_proof(
                reference, stored.tree_size, candidate.tree_size
            )
            if not verify_consistency(
                stored.tree_size,
                candidate.tree_size,
                stored.root_hash,
                candidate.root_hash,
                proof,
            ):
                raise C2spCheckpointConsistencyError(
                    "stream bundle checkpoint consistency proof is invalid",
                    category=C2spLifecycleErrorCategory.LOG_INCONSISTENT,
                    trusted=stored,
                    observed=candidate,
                )
            return
        if complete_entries is not None:
            try:
                _verify_checkpoint_prefix(entries, stored, "previously trusted")
            except C2spTlogVerificationError as exc:
                raise C2spCheckpointConsistencyError(
                    "stream bundle checkpoint is not consistent with previously trusted prefix",
                    category=C2spLifecycleErrorCategory.LOG_INCONSISTENT,
                    trusted=stored,
                    observed=candidate,
                ) from exc
            return
        raise _MissingC2spConsistencyEvidenceError(
            "stream bundle checkpoint growth requires a consistency-proof source"
        )

    options.checkpoint_store.verify_and_advance(candidate, _verify)


def _verified_complete_scan_entries(evidence: C2spStreamEvidence) -> list[IndexedEntry]:
    if not evidence.complete:
        raise C2spTlogVerificationError(
            "stream bundle consistency fallback requires a complete raw scan"
        )
    entries = sorted(evidence.entries, key=lambda entry: entry.index)
    if len(entries) != evidence.checkpoint.tree_size:
        raise C2spTlogVerificationError(
            "complete raw scan length does not match its checkpoint"
        )
    _verify_checkpoint_prefix(entries, evidence.checkpoint, "raw scan")
    return entries


def _verify_checkpoint_prefix(
    entries: list[IndexedEntry],
    checkpoint: Checkpoint | TrustedCheckpoint,
    name: str,
) -> None:
    prefix = entries[: checkpoint.tree_size]
    if len(prefix) != checkpoint.tree_size or any(
        entry.index != index for index, entry in enumerate(prefix)
    ):
        raise C2spTlogVerificationError(
            f"complete scan does not contain the {name} checkpoint prefix"
        )
    if merkle_root_from_entries([entry.data for entry in prefix]) != checkpoint.root_hash:
        raise C2spTlogVerificationError(
            f"complete scan prefix does not match the {name} checkpoint"
        )


def _verify_bundle_signature(
    obj: dict[str, object],
    bundle_keys: list[SignedNoteKey],
    policy: C2spTlogPolicy,
    reference: ParsedC2spTlogLr,
) -> str:
    sig = _exact_object(obj["sig"], _SIG_MEMBERS, "stream bundle sig")
    if sig["alg"] != "EdDSA":
        raise C2spTlogVerificationError("unsupported stream bundle signature algorithm")
    kid = _string(sig["kid"], "sig.kid")
    candidates = [key for key in bundle_keys if _bundle_kid(key) == kid]
    if len(candidates) != 1:
        raise C2spTlogVerificationError("stream bundle signer is not uniquely trusted")
    key = candidates[0]
    if (
        key.kind != "ed25519"
        or len(key.key_bytes) != 32
        or key.signature_type not in (None, b"\x01")
    ):
        raise C2spTlogVerificationError("stream bundle signer must be Ed25519")
    accepted_policy = normalized_origin_policy(policy, reference.origin)
    checkpoint_key_bytes = {
        item.key_bytes
        for item in [*accepted_policy.log_keys, *accepted_policy.witness_keys]
    }
    if key.key_bytes in checkpoint_key_bytes:
        raise C2spTlogVerificationError(
            "stream bundle signer must be independent of checkpoint policy keys"
        )
    signature = _decode_b64(sig["value"], "sig.value")
    if len(signature) != 64:
        raise C2spTlogVerificationError("stream bundle signature must be 64 bytes")
    unsigned = dict(obj)
    del unsigned["sig"]
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(key.key_bytes).verify(
            signature, canonical_bytes(unsigned)
        )
    except (InvalidSignature, ValueError) as exc:
        raise C2spTlogVerificationError("invalid stream bundle signature") from exc
    return kid


def _parse_and_verify_events(
    raw_events: list[object], checkpoint: Checkpoint
) -> list[IndexedEntry]:
    entries: list[IndexedEntry] = []
    previous_index = -1
    for raw in raw_events:
        event = _exact_object(raw, _EVENT_MEMBERS, "stream bundle event")
        index = _safe_int(event["index"], "event.index")
        if index <= previous_index or index >= checkpoint.tree_size:
            raise C2spTlogVerificationError(
                "stream bundle event indexes must be unique, increasing, and in range"
            )
        previous_index = index
        entry = _decode_b64(event["entry"], "event.entry")
        proof_bytes = _decode_b64(event["proof"], "event.proof", allow_empty=True)
        if not 1 <= len(entry) <= 65535:
            raise C2spTlogVerificationError("stream bundle event entry size is invalid")
        if len(proof_bytes) % 32 or len(proof_bytes) // 32 > 64:
            raise C2spTlogVerificationError("stream bundle event proof length is invalid")
        proof = [proof_bytes[offset : offset + 32] for offset in range(0, len(proof_bytes), 32)]
        if not verify_inclusion(
            entry, index, checkpoint.tree_size, checkpoint.root_hash, proof
        ):
            raise C2spTlogVerificationError(
                f"invalid stream bundle inclusion proof at index {index}"
            )
        entries.append(IndexedEntry(index=index, data=entry))
    return entries


def _bundle_kid(key: SignedNoteKey) -> str | None:
    if key.key_id is None or len(key.key_id) != 4:
        return None
    return f"{key.name}+{key.key_id.hex()}"


def _active_operational_thumbprint(
    events: list[VerifiedLifecycleEvent],
    migration_results: dict[int, MigrationVerificationResult],
) -> str:
    active: JWK | None = None
    for item in events:
        event = item.event
        if isinstance(event, IssuanceEvent):
            active = event.operational_key
        elif isinstance(event, MigrationEvent):
            migrated = migration_results.get(id(event))
            if migrated is not None:
                active = migrated.operational_key
        elif isinstance(event, KeyRotationEvent):
            active = event.new_public_key
    if active is None:
        raise C2spTlogVerificationError(
            "stream bundle replay did not establish an operational key"
        )
    return active.thumbprint()


def _logged_state(events: list[VerifiedLifecycleEvent]) -> str:
    from ..models import RetirementEvent, RevocationEvent

    final = events[-1].event
    if isinstance(final, RevocationEvent):
        return "REVOKED"
    if isinstance(final, RetirementEvent):
        return "RETIRED"
    return "ACTIVE"


def _decode_b64(value: object, name: str, *, allow_empty: bool = False) -> bytes:
    text = _string(value, name)
    if allow_empty and text == "":
        return b""
    try:
        decoded = b64url_decode_strict(text)
    except ValueError as exc:
        raise C2spTlogParseError(f"{name} is not canonical unpadded base64url") from exc
    if b64url_encode(decoded) != text:
        raise C2spTlogParseError(f"{name} is not canonical unpadded base64url")
    return decoded


def _exact_object(
    value: object, members: frozenset[str], name: str
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != members:
        raise C2spTlogParseError(f"{name} must contain exactly its required members")
    return value


def _string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise C2spTlogParseError(f"{name} must be a string")
    return value


def _safe_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_SAFE_INT:
        raise C2spTlogParseError(f"{name} must be a non-negative safe integer")
    return value


def _assert_all_safe_integers(value: object) -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        _safe_int(value, "stream bundle integer")
        return
    if isinstance(value, list):
        for item in value:
            _assert_all_safe_integers(item)
        return
    if isinstance(value, dict):
        for item in value.values():
            _assert_all_safe_integers(item)
        return
    raise C2spTlogParseError("stream bundle values must be I-JSON integers or strings")
