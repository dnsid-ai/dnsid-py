"""C2spTlogReader — the LogReader implementation for the c2sp-tlog method."""

from __future__ import annotations

import datetime
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import wraps
from typing import ParamSpec, TypeVar, cast

from .._utils import parse_ledger_ref
from .._verification_budget import verification_operation
from ..exceptions import ParseError
from ..interfaces import KeyProvider as KeyProviderT
from ..interfaces import LogReader
from ..models import (
    JWK,
    AnyLogEvent,
    DomainLog,
    IssuanceEvent,
    KeyRotationEvent,
    LogEvent,
    LoggedStateEvidence,
    LogRef,
    MigrationEvent,
    RevocationEvent,
    VerifiedCutoffHistory,
)
from . import prepared as prepared_mod
from .checkpoint import Checkpoint
from .checkpoint_store import (
    CheckpointStore,
    InMemoryCheckpointStore,
    TrustedCheckpoint,
)
from .errors import (
    C2spCheckpointConsistencyError,
    C2spLifecycleErrorCategory,
    C2spTlogError,
    C2spTlogTransportError,
    C2spTlogVerificationError,
)
from .event_codec import (
    C2spEventContext,
    parse_c2sp_event_entry,
    signed_c2sp_event_bytes,
)
from .lr import ParsedC2spTlogLr, parse_c2sp_tlog_lr
from .merkle import merkle_root_from_entries
from .policy import (
    C2spTlogPolicy,
    enforce_checkpoint_policy,
    normalized_origin_policy,
)
from .proof import TlogProofV1, verify_c2sp_tlog_proof
from .resource_fetcher import C2spBoundedResourceFetcher
from .signed_note import SignedNoteKey
from .stream_bundle import _FetchedStreamBundleSource
from .stream_source import (
    C2spScanLimits,
    C2spTlogSource,
    C2spTlogTransport,
    ScanStreamSource,
    StreamEvidence,
    enforce_public_read_guarantees,
)
from .stream_verifier import (
    MigrationVerificationResult,
    StreamVerifierOptions,
    VerifiedLifecycleEvent,
    verify_occurrence,
    verify_stream_lifecycle,
)

_DEFAULT_MAX_MIGRATION_DEPTH = 8
_DEFAULT_MAX_MIGRATION_HISTORY_EVENTS = 10_000
_DEFAULT_MAX_MIGRATION_RESPONSE_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class C2spMigrationVerificationLimits:
    """Cumulative bounds for recursive previous-log verification."""

    max_depth: int = _DEFAULT_MAX_MIGRATION_DEPTH
    max_history_events: int = _DEFAULT_MAX_MIGRATION_HISTORY_EVENTS
    max_response_bytes: int = _DEFAULT_MAX_MIGRATION_RESPONSE_BYTES

    def __post_init__(self) -> None:
        """Require finite positive limits."""
        for name in ("max_depth", "max_history_events", "max_response_bytes"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise C2spTlogVerificationError(
                    f"{name} must be a positive integer"
                )


@dataclass
class _MigrationBudget:
    limits: C2spMigrationVerificationLimits
    seen: set[str]
    history_events: int = 0
    response_bytes: int = 0
    active: bool = False

    def add_response(self, size: int) -> None:
        self.response_bytes += size
        self._enforce()

    def add_events(self, count: int) -> None:
        self.history_events += count
        self._enforce()

    def activate(self) -> None:
        self.active = True
        self._enforce()

    def _enforce(self) -> None:
        if not self.active:
            return
        if self.history_events > self.limits.max_history_events:
            raise C2spTlogVerificationError(
                "recursive MIGRATION history exceeds configured event maximum "
                f"{self.limits.max_history_events}",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )
        if self.response_bytes > self.limits.max_response_bytes:
            raise C2spTlogVerificationError(
                "recursive MIGRATION responses exceed configured byte maximum "
                f"{self.limits.max_response_bytes}",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )


@dataclass(frozen=True)
class _MigrationContext:
    budget: _MigrationBudget
    depth: int = 0


@dataclass
class C2spTlogReaderOptions:
    """Configuration for :class:`C2spTlogReader`.

    *policy* is the local checkpoint trust policy (per-origin log keys,
    witness keys, quorum).  *transport* fetches URLs and must raise on HTTP
    errors (a testnet deployment typically routes it through the testnet DNS
    and CA).  *proofs* pre-supplies TlogProofV1 inclusion proofs keyed by
    entry index (as a string).  *entity_key* is the trusted entity key that
    anchors lifecycle verification (identity pinning).  *max_clock_skew_ms*
    is the tolerated clock skew for checkpoint/cosignature timestamps.
    *checkpoint_freshness_ms* bounds checkpoint staleness for non-revocation.
    *max_tree_size* is an upper bound on the accepted tree size (resource
    guard). *scan_limits* configures all resource bounds of the built-in
    complete scanner; when both are set, *max_tree_size* takes precedence.
    *migration_limits* bounds recursive depth, cumulative stitched events, and
    cumulative response bytes. *migration_reader_factory* is the advanced
    low-level hook used to construct fully verifying predecessor readers; the
    standard registries configure it automatically. *checkpoint_store* records
    the highest trusted checkpoint per origin so a later verification cannot
    accept a forked or rolled-back tree; share one options instance across
    readers so the state accumulates.
    For ``public`` scope, an injected source or transport must expose
    ``security_guarantees()`` and demonstrate the complete public bounded-read
    capability contract, including DNS-rebinding and redirect protections.
    A scan transport must also implement ``fetch_bounded(url, maximum)``.
    Supplying independently trusted ``bundle_keys`` and the exact
    ``bundle_policy_document`` prefers bounded per-domain stream bundles;
    the scanner remains the availability and consistency fallback.
    """

    policy: C2spTlogPolicy
    transport: C2spTlogTransport | None = None
    source: C2spTlogSource | None = None
    proofs: dict[str, TlogProofV1 | str] = field(default_factory=dict)
    unchained: bool | None = None
    entity_key: JWK | None = None
    max_clock_skew_ms: int = 0
    checkpoint_freshness_ms: int | None = None
    max_tree_size: int | None = None
    scan_limits: C2spScanLimits | None = None
    migration_limits: C2spMigrationVerificationLimits = field(
        default_factory=C2spMigrationVerificationLimits
    )
    migration_reader_factory: Callable[[str], LogReader] | None = field(
        default=None, repr=False
    )
    checkpoint_store: CheckpointStore = field(default_factory=InMemoryCheckpointStore)
    bundle_policy_document: bytes | None = None
    bundle_keys: list[SignedNoteKey] = field(default_factory=list)
    bundle_checkpoint_freshness_ms: int = 300_000
    max_bundle_lifetime_ms: int = 300_000
    max_bundle_bytes: int = 8 * 1024 * 1024
    max_bundle_events: int = 10_000
    require_stream_bundle: bool = False


@dataclass
class BilateralBindingResult:
    """Outcome of verify_bilateral_binding: the logged initial anchors."""

    initial_operational_thumbprint: str
    initial_entity_thumbprint: str
    timestamp: datetime.datetime


@dataclass
class _VerifiedHistory:
    events: list[AnyLogEvent]
    checkpoint_witness_time: datetime.datetime
    complete_through: object
    completeness_mode: str
    checkpoint: object
    evidence_expires_at: datetime.datetime | None = None
    current_stream_events: list[VerifiedLifecycleEvent] = field(default_factory=list)
    event_refs: list[str] = field(default_factory=list)


_P = ParamSpec("_P")
_R = TypeVar("_R")


def _verification_boundary(func: Callable[_P, _R]) -> Callable[_P, _R]:
    """Adapt binding and transport failures at the shared LogReader boundary."""

    @wraps(func)
    def wrapped(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        from ..exceptions import VerificationError

        try:
            return func(*args, **kwargs)
        except VerificationError:
            raise
        except C2spTlogError as exc:
            raise _adapt_c2sp_error(exc) from exc
        except (ConnectionError, OSError, TimeoutError) as exc:
            transport_error = C2spTlogTransportError(
                "C2SP verification resource is unavailable",
                transient=True,
                cause=exc,
            )
            raise _adapt_c2sp_error(transport_error) from exc

    return verification_operation(wrapped)


class C2spTlogReader(LogReader):
    """LogReader over a C2SP tile log, verified against a local trust policy.

    Read paths authenticate the checkpoint and select the signed lifecycle
    from either a strictly verified per-domain bundle or a complete raw scan.

    For a draft 01 record this reader performs the binding-level lifecycle
    checks verify_domain requires:

    * Checkpoint authentication — signed-note signature against the pinned
      log key plus witness-quorum cosignatures, with append-only consistency
      against the stored trusted checkpoint (anti-rollback).
    * Stream lifecycle verification — scans every entry of the identity's
      stream and selects the entries forming a valid signed lifecycle: an
      ISSUANCE (or verified MIGRATION genesis) establishing the entity and
      operational keys, followed by rotations and entity-signed lifecycle
      events, with logical-event hash chaining in every scope.
    * Bilateral ISSUANCE binding — the record's ek/ku anchors must match the
      logged entity and operational keys, both signatures verified
      (:meth:`verify_bilateral_binding`).
    * Operational continuity — the current operational key must descend from
      the logged initial operational key through recorded rotations.
    * Non-termination — no REVOCATION or RETIREMENT event for the domain, under a
      sufficiently fresh checkpoint (``checkpoint_freshness_ms``).
    * Merkle inclusion — entry inclusion proofs against the checkpoint root.
    """

    def __init__(self, lr: str, options: C2spTlogReaderOptions) -> None:
        """Bind a reader to the stream addressed by *lr* and validate *options*.

        Raises:
            C2spTlogParseError: If *lr* is not a valid c2sp-tlog reference.
            C2spTlogVerificationError: If *options* is invalid (negative
                clock skew, or neither/both of transport and source given).
        """
        self.parsed: ParsedC2spTlogLr = parse_c2sp_tlog_lr(lr)
        if self.parsed.entry_index is not None:
            raise C2spTlogVerificationError(
                "C2spTlogReader requires a bound log reference without @index"
            )
        self.lr = self.parsed.lr
        self._options = options
        if type(options.max_clock_skew_ms) is not int or options.max_clock_skew_ms < 0:
            raise C2spTlogVerificationError(
                "max_clock_skew_ms must be a non-negative integer"
            )
        if (
            options.checkpoint_freshness_ms is not None
            and (
                type(options.checkpoint_freshness_ms) is not int
                or options.checkpoint_freshness_ms < 1
            )
        ):
            raise C2spTlogVerificationError(
                "checkpoint_freshness_ms must be a positive integer when supplied"
            )
        if options.max_tree_size is not None and (
            type(options.max_tree_size) is not int or options.max_tree_size < 1
        ):
            raise C2spTlogVerificationError(
                "max_tree_size must be a positive integer when supplied"
            )
        if not isinstance(options.migration_limits, C2spMigrationVerificationLimits):
            raise C2spTlogVerificationError(
                "migration_limits must be C2spMigrationVerificationLimits"
            )
        if type(options.require_stream_bundle) is not bool:
            raise C2spTlogVerificationError("require_stream_bundle must be a boolean")
        if options.require_stream_bundle and not options.bundle_keys:
            raise C2spTlogVerificationError(
                "require_stream_bundle requires trusted bundle keys"
            )
        if options.bundle_keys:
            if not isinstance(options.bundle_policy_document, bytes):
                raise C2spTlogVerificationError(
                    "stream bundles require the exact trusted policy document"
                )
            for name in (
                "bundle_checkpoint_freshness_ms",
                "max_bundle_lifetime_ms",
                "max_bundle_bytes",
                "max_bundle_events",
            ):
                value = getattr(options, name)
                if type(value) is not int or value < 1:
                    raise C2spTlogVerificationError(
                        f"{name} must be a positive integer"
                    )
        if options.transport is None and options.source is None:
            raise C2spTlogVerificationError(
                "C2spTlogReader requires a transport or C2spTlogSource"
            )
        if options.transport is not None and options.source is not None:
            raise C2spTlogVerificationError(
                "C2spTlogReader accepts either transport or source, not both"
            )
        if options.bundle_keys and options.source is not None:
            raise C2spTlogVerificationError(
                "stream bundle fetching requires a transport"
            )
        kwargs: dict[str, int] = {}
        if options.scan_limits is not None:
            limits = options.scan_limits
            kwargs = {
                "max_tree_size": limits.max_tree_size,
                "max_checkpoint_bytes": limits.max_checkpoint_bytes,
                "max_entry_bundle_bytes": limits.max_entry_bundle_bytes,
                "max_total_entry_bytes": limits.max_total_entry_bytes,
            }
        if options.max_tree_size is not None:
            kwargs["max_tree_size"] = options.max_tree_size
        if options.source is not None:
            self._source: C2spTlogSource = options.source
        else:
            assert options.transport is not None
            scan_source = ScanStreamSource(
                options.transport,
                self._authenticate_checkpoint,
                **kwargs,
            )
            self._source = scan_source
            if options.bundle_keys:
                if not callable(getattr(options.transport, "fetch_bounded", None)):
                    raise C2spTlogVerificationError(
                        "stream bundles require a bounded resource fetcher"
                    )
                assert options.bundle_policy_document is not None
                self._source = _FetchedStreamBundleSource(
                    cast(C2spBoundedResourceFetcher, options.transport),
                    scan_source,
                    policy_bytes=options.bundle_policy_document,
                    bundle_keys=options.bundle_keys,
                    checkpoint_freshness_ms=(
                        options.bundle_checkpoint_freshness_ms
                    ),
                    max_bundle_lifetime_ms=options.max_bundle_lifetime_ms,
                    max_bundle_bytes=options.max_bundle_bytes,
                    max_events=options.max_bundle_events,
                    max_tree_size=kwargs.get("max_tree_size", 1_000_000),
                    max_clock_skew_ms=options.max_clock_skew_ms,
                    checkpoint_store=options.checkpoint_store,
                    require_bundle=options.require_stream_bundle,
                )
        if self.parsed.scope == "public":
            enforce_public_read_guarantees(self._source, self.parsed)
        self._trusted_entity_key: JWK | None = None
        # One full verification shares a single policy-verified history across
        # bilateral binding, continuity, non-revocation, and key-age checks.
        # Status-only cache refreshes retain the reader, so expired bundle or
        # non-revocation evidence is evicted before a later policy check.
        self._history_cache: dict[tuple[str, str], _VerifiedHistory] = {}

    # ------------------------------------------------------------------
    # LogReader interface
    # ------------------------------------------------------------------

    @_verification_boundary
    def canonical(self, event: LogEvent) -> bytes:
        """Return the canonical signed C2SP entry bytes for *event*.

        In every scope only an ISSUANCE can be canonicalized here;
        later events must go through the prepared-event API.

        Raises:
            C2spTlogParseError: If the event cannot be encoded as a C2SP
                entry (for example, missing key metadata).
            VerificationError: With ``VerificationCode.LOG_ERROR`` if the
                event type is unsupported or requires the prepared-event API.
        """
        any_event = _as_any_event(event)
        if not isinstance(any_event, IssuanceEvent):
            raise _log_error("c2sp-tlog events after ISSUANCE require the prepared-event API")
        context = self._context()
        context.seq = 0
        return signed_c2sp_event_bytes(any_event, context)

    @_verification_boundary
    def key_timestamp(self, domain: str, key_thumbprint: str) -> datetime.datetime:
        """Return when *key_thumbprint* became an operational key for *domain*.

        The timestamp comes from the verified lifecycle event (ISSUANCE or
        KEY_ROTATION) that introduced the key.

        Raises:
            VerificationError: With ``VerificationCode.LOG_ERROR`` if the
                thumbprint does not appear in the verified history or the
                history itself cannot be loaded and verified.
        """
        for event in self.rebuild_history(domain):
            if (
                isinstance(event, IssuanceEvent)
                and event.operational_key is not None
                and event.operational_key.thumbprint() == key_thumbprint
            ):
                return event.timestamp
            if (
                isinstance(event, KeyRotationEvent)
                and event.new_thumbprint == key_thumbprint
            ):
                return event.timestamp
        raise _log_error("key thumbprint not found in C2SP lifecycle history")

    @_verification_boundary
    def preload_history(self, domain: str, entity_key: JWK) -> None:
        """Fetch and verify the complete history for *domain* under *entity_key*.

        Warms the same cache :meth:`verify_bilateral_binding` reads, so callers
        can overlap the log fetch with other independent network work. Raises
        exactly what the later binding check would have raised.
        """
        self._load_complete_history(domain, entity_key)

    @_verification_boundary
    def verify_bilateral_binding(
        self,
        record: object,
        entity_key: JWK,
        operational_key: JWK,
    ) -> BilateralBindingResult:
        """Verify the record's ek/ku anchors against the logged lifecycle.

        Loads the complete verified history anchored on *entity_key* (which
        becomes this reader's trusted entity key for later calls), and checks
        that the ISSUANCE matches the record's domain and governance ID, its
        entity key matches the current ek anchor, and the current operational
        key is recorded in the lifecycle (initial or via rotation).
        """
        domain = getattr(record, "identity_fqdn", "") or getattr(record, "domain", "")
        if not domain:
            raise _log_error("cannot infer domain for bilateral binding")
        initial_entity_thumbprint = entity_key.thumbprint()
        verified = self._load_complete_history(domain, entity_key)
        snapshot = DomainLog(domain, list(verified.events)).snapshot_at(
            max(event.timestamp for event in verified.events)
        )
        if snapshot.historical_state != "ACTIVE":
            raise _log_error(
                f"complete lifecycle history is terminal: {snapshot.historical_state}"
            )
        self._trusted_entity_key = entity_key
        issuance = next(
            (e for e in verified.events if isinstance(e, IssuanceEvent)), None
        )
        if issuance is None:
            raise _log_error("ISSUANCE not found")
        if issuance.entity_key is None or issuance.operational_key is None:
            raise _log_error("ISSUANCE is missing c2sp-tlog key metadata")
        record_gi = getattr(record, "gi", None)
        if issuance.domain != domain or issuance.governance_id != record_gi:
            raise _log_error(
                "ISSUANCE does not match current domain and governance ID"
            )
        if issuance.entity_key.thumbprint() != initial_entity_thumbprint:
            raise _log_error("ISSUANCE entity key does not match current ek key")
        current_operational_thumbprint = operational_key.thumbprint()
        recorded = any(
            (
                isinstance(e, IssuanceEvent)
                and e.operational_key is not None
                and e.operational_key.thumbprint() == current_operational_thumbprint
            )
            or (
                isinstance(e, KeyRotationEvent)
                and e.new_thumbprint == current_operational_thumbprint
            )
            for e in verified.events
        )
        if not recorded:
            raise _log_error(
                "current operational key is not recorded in lifecycle history"
            )
        return BilateralBindingResult(
            initial_operational_thumbprint=issuance.operational_key.thumbprint(),
            initial_entity_thumbprint=initial_entity_thumbprint,
            timestamp=issuance.timestamp,
        )

    @_verification_boundary
    def verify_operational_continuity(
        self,
        domain: str,
        initial_operational_thumbprint: str,
        current_operational_thumbprint: str,
    ) -> None:
        """Verify the active operational key follows from the initial one."""
        from ..models import DomainLog

        verified = self._load_complete_history(domain)
        first = next(
            (e for e in verified.events if isinstance(e, IssuanceEvent)), None
        )
        if (
            first is None
            or first.operational_key is None
            or first.operational_key.thumbprint() != initial_operational_thumbprint
        ):
            raise _log_error("initial operational key mismatch")
        snap = DomainLog(domain, list(verified.events)).snapshot_at(
            max(event.timestamp for event in verified.events)
        )
        if snap.historical_state != "ACTIVE":
            raise _log_error(
                f"complete lifecycle history is terminal: {snap.historical_state}"
            )
        if snap.active_key_thumbprint != current_operational_thumbprint:
            raise _log_error("current operational key mismatch")

    @_verification_boundary
    def verify_non_revocation(
        self, domain: str, at: datetime.datetime
    ) -> LoggedStateEvidence:
        """Verify complete, fresh logged history for *domain* as of *at*.

        Requires ``checkpoint_freshness_ms`` to be configured and the
        checkpoint's witness time to be within that bound.

        Returns:
            The accepted completeness, checkpoint, and freshness boundary.

        Raises:
            VerificationError: With ``VerificationCode.LOG_ERROR`` if the
                domain was revoked or retired at or before *at*, the checkpoint is too
                stale, or the history cannot be loaded and verified.
        """
        verified = self._load_complete_history(domain, require_fresh=True)
        self._assert_fresh(verified.checkpoint_witness_time)
        snapshot = DomainLog(domain, list(verified.events)).snapshot_at(at)
        if snapshot.historical_state in ("REVOKED", "RETIRED"):
            raise _log_error(
                f"domain {domain} was {snapshot.historical_state.lower()}"
            )
        history_end_index = len(snapshot.events) - 1
        if len(verified.event_refs) != len(verified.events):
            raise _log_error(
                "C2SP verified history is missing event references",
                C2spLifecycleErrorCategory.INVALID_EVIDENCE,
            )
        return LoggedStateEvidence(
            log_reference=self.parsed.lr,
            logged_state=snapshot.historical_state,
            history_start=verified.event_refs[0],
            history_end=verified.event_refs[history_end_index],
            complete_through=verified.complete_through,
            completeness_mode=verified.completeness_mode,
            checkpoint=verified.checkpoint,
            freshness_time=verified.checkpoint_witness_time,
        )

    @_verification_boundary
    def read_event(self, ref: LogRef) -> AnyLogEvent:
        """Read and verify the single logged event addressed by *ref*.

        The reference must belong to this reader's stream and carry an
        ``@index``; a matching entry in ``options.proofs`` supplies the
        tlog-proof.  The entry is checked for inclusion under a
        policy-accepted checkpoint and must be authorized by the verified
        lifecycle history of its domain.

        Returns:
            The parsed, lifecycle-authorized event.

        Raises:
            C2spTlogParseError: If *ref* or the entry bytes are malformed.
            VerificationError: With ``VerificationCode.LOG_ERROR`` if the
                proof, checkpoint policy, timestamp, or lifecycle
                authorization checks fail.
        """
        parsed = parse_c2sp_tlog_lr(str(ref))
        if (
            parsed.scope != self.parsed.scope
            or parsed.log_prefix != self.parsed.log_prefix
            or parsed.stream_id != self.parsed.stream_id
        ):
            raise _log_error("C2SP event ref does not belong to this reader")
        if parsed.entry_index is None:
            raise _log_error("C2SP event ref missing @index")
        proof = self._options.proofs.get(str(parsed.entry_index))
        if proof is None:
            raise _log_error(
                "C2SP read_event requires a proof/source for historical inclusion"
            )
        evidence = self._source.load_stream(parsed, parsed.stream_id)
        entry = next(
            (e for e in evidence.entries if e.index == parsed.entry_index), None
        )
        if entry is None:
            raise _log_error("C2SP entry not found in source")
        verified_proof = verify_c2sp_tlog_proof(
            entry.data,
            proof,
            self._options.policy,
            parsed.origin,
            parsed.scope,
            self._now_ms(),
            self._options.max_clock_skew_ms,
        )
        if verified_proof.index != parsed.entry_index:
            raise _log_error("C2SP proof index mismatch")
        event = parse_c2sp_event_entry(entry.data, self._context(parsed))
        proof_policy = enforce_checkpoint_policy(
            verified_proof.checkpoint,
            parsed.origin,
            self._options.policy,
            parsed.scope,
            self._now_ms(),
            self._options.max_clock_skew_ms,
        )
        if proof_policy.checkpoint_witness_time is None:
            raise _log_error(
                "C2SP proof timestamp requires an accepted timestamped witness quorum"
            )
        proof_time_ms = proof_policy.checkpoint_witness_time.timestamp() * 1000
        if (
            event.timestamp.timestamp() * 1000
            > proof_time_ms + self._options.max_clock_skew_ms
        ):
            raise _log_error(
                "C2SP event timestamp is later than its proof checkpoint integration time"
            )
        entity_key = self._options.entity_key or self._trusted_entity_key
        if entity_key is None:
            raise _log_error("C2SP read_event requires a trusted entity key")
        if isinstance(self._source, _FetchedStreamBundleSource):
            history = self._load_complete_history(event.domain, entity_key)
            return verify_occurrence(
                entry, history.current_stream_events,
                self._verifier_options(parsed, entity_key, history.checkpoint_witness_time),
            ).event
        if not evidence.complete:
            raise _log_error(
                "C2SP read_event requires complete lifecycle evidence for "
                "event authorization"
            )
        policy_result = enforce_checkpoint_policy(
            evidence.checkpoint,
            parsed.origin,
            self._options.policy,
            parsed.scope,
            self._now_ms(),
            self._options.max_clock_skew_ms,
        )
        if policy_result.checkpoint_witness_time is None:
            raise _log_error(
                "C2SP event timestamp requires an accepted timestamped witness quorum"
            )
        _assert_complete_scan(evidence)
        self._enforce_append_only_consistency(
            evidence, policy_result.checkpoint_witness_time
        )
        migration_context = _MigrationContext(
            _MigrationBudget(self._options.migration_limits, {self.parsed.lr})
        )
        migration_context.budget.add_response(_stream_evidence_bytes(evidence))
        verifier_options = self._verifier_options(
            parsed, entity_key, policy_result.checkpoint_witness_time
        )

        def verify_migration(migration: MigrationEvent) -> MigrationVerificationResult:
            return self._verify_prior_history(
                migration, event.domain, entity_key, migration_context
            )

        verifier_options.verify_migration = verify_migration
        verified = verify_stream_lifecycle(
            evidence.entries, event.domain, verifier_options
        )
        migration_context.budget.add_events(len(verified))
        return verify_occurrence(entry, verified, verifier_options).event

    @_verification_boundary
    def rebuild_history(self, domain: str) -> list[AnyLogEvent]:
        """Return the verified lifecycle events for *domain* in log order.

        Raises:
            VerificationError: With ``VerificationCode.LOG_ERROR`` if the
                stream cannot be completely loaded, checked against the
                checkpoint, and verified under the trusted entity key.
        """
        return self._load_complete_history(domain).events

    @_verification_boundary
    def rebuild_history_through(
        self,
        domain: str,
        final_entry_ref: str,
        entity_key: JWK,
        *,
        max_depth: int,
        max_events: int,
        max_response_bytes: int,
        seen_log_references: frozenset[str],
    ) -> VerifiedCutoffHistory:
        """Verify this stream through exactly *final_entry_ref*."""
        cutoff = parse_c2sp_tlog_lr(final_entry_ref)
        if (
            cutoff.entry_index is None
            or cutoff.lr != self.parsed.lr
            or final_entry_ref != _event_ref(self.parsed.lr, cutoff.entry_index)
        ):
            raise C2spTlogVerificationError(
                "MIGRATION prev_ref must exactly identify an entry in prev_lr",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )
        limits = C2spMigrationVerificationLimits(
            max_depth=max_depth,
            max_history_events=max_events,
            max_response_bytes=max_response_bytes,
        )
        budget = _MigrationBudget(limits, set(seen_log_references) | {self.parsed.lr})
        budget.activate()
        history = self._load_complete_history(
            domain,
            entity_key,
            cutoff_index=cutoff.entry_index,
            migration_context=_MigrationContext(budget),
        )
        if not history.event_refs or history.event_refs[-1] != final_entry_ref:
            raise C2spTlogVerificationError(
                "MIGRATION prior history does not end at the signed cutoff",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )
        return VerifiedCutoffHistory(
            list(history.events), list(history.event_refs), budget.response_bytes
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _authenticate_checkpoint(self, checkpoint: Checkpoint) -> None:
        try:
            enforce_checkpoint_policy(
                checkpoint,
                self.parsed.origin,
                self._options.policy,
                self.parsed.scope,
                self._now_ms(),
                self._options.max_clock_skew_ms,
            )
        except C2spTlogVerificationError as exc:
            if exc.category is None:
                exc.category = C2spLifecycleErrorCategory.INVALID_EVIDENCE
            raise

    def _load_complete_history(
        self,
        domain: str,
        entity_key: JWK | None = None,
        *,
        require_fresh: bool = False,
        cutoff_index: int | None = None,
        migration_context: _MigrationContext | None = None,
    ) -> _VerifiedHistory:
        trusted = entity_key or self._options.entity_key or self._trusted_entity_key
        if trusted is None:
            raise _log_error("C2SP lifecycle verification requires a trusted entity key")
        cache_key = (domain, trusted.thumbprint())
        use_cache = cutoff_index is None and migration_context is None
        cached = self._history_cache.get(cache_key) if use_cache else None
        if cached is not None:
            expired = (
                cached.evidence_expires_at is not None
                and self._now_ms() >= cached.evidence_expires_at.timestamp() * 1000
            )
            stale = require_fresh and self._checkpoint_is_stale(
                cached.checkpoint_witness_time
            )
            if not expired and not stale:
                return cached
            del self._history_cache[cache_key]

        context = migration_context or _MigrationContext(
            _MigrationBudget(self._options.migration_limits, {self.parsed.lr})
        )
        migration_results: dict[int, MigrationVerificationResult] = {}

        def verify_migration(event: MigrationEvent) -> MigrationVerificationResult:
            cached_result = migration_results.get(id(event))
            if cached_result is not None:
                return cached_result
            result = self._verify_prior_history(event, domain, trusted, context)
            migration_results[id(event)] = result
            return result

        if isinstance(self._source, _FetchedStreamBundleSource):
            bundle = self._source.load_verified_bundle(
                self.parsed,
                domain,
                trusted,
                verify_migration,
                cutoff_index=cutoff_index,
                account_response=context.budget.add_response,
            )
            if bundle is not None:
                if bundle.reference.lr != self.lr:
                    raise C2spTlogVerificationError(
                        "stream bundle lr does not exactly match authenticated record"
                    )
                self._assert_cutoff(bundle.events, cutoff_index)
                context.budget.add_events(len(bundle.events))
                events = [item.event for item in bundle.events]
                events = _stitch_migration_history(
                    domain, events, bundle.migration_results
                )
                result = _VerifiedHistory(
                    events=events,
                    checkpoint_witness_time=bundle.checkpoint_witness_time,
                    complete_through=bundle.checkpoint.tree_size,
                    completeness_mode="trusted-index",
                    checkpoint=bundle.checkpoint_bytes or bundle.checkpoint,
                    evidence_expires_at=datetime.datetime.fromtimestamp(
                        bundle.expires, tz=datetime.UTC
                    ),
                    current_stream_events=list(bundle.events),
                    event_refs=_stitched_event_refs(
                        self.parsed.lr, bundle.events, bundle.migration_results
                    ),
                )
                if use_cache:
                    self._history_cache[cache_key] = result
                return result

        evidence = self._source.load_stream(self.parsed, domain)
        context.budget.add_response(_stream_evidence_bytes(evidence))
        if (
            self._options.max_tree_size is not None
            and evidence.checkpoint.tree_size > self._options.max_tree_size
        ):
            raise _log_error(
                "checkpoint tree size exceeds configured maximum "
                f"{self._options.max_tree_size}"
            )
        if not evidence.complete:
            raise _log_error(
                "C2SP stream source is incomplete for current-state verification",
                C2spLifecycleErrorCategory.INCOMPLETE_STREAM,
            )
        try:
            policy_result = enforce_checkpoint_policy(
                evidence.checkpoint,
                self.parsed.origin,
                self._options.policy,
                self.parsed.scope,
                self._now_ms(),
                self._options.max_clock_skew_ms,
            )
        except C2spTlogVerificationError as exc:
            if exc.category is None:
                exc.category = C2spLifecycleErrorCategory.INVALID_EVIDENCE
            raise
        if policy_result.checkpoint_witness_time is None:
            raise _log_error(
                "C2SP lifecycle timestamps require an accepted timestamped witness quorum",
                C2spLifecycleErrorCategory.INVALID_EVIDENCE,
            )
        _assert_complete_scan(evidence)
        self._enforce_append_only_consistency(
            evidence, policy_result.checkpoint_witness_time
        )
        verifier_options = self._verifier_options(
            self.parsed, trusted, policy_result.checkpoint_witness_time
        )
        verifier_options.verify_migration = verify_migration
        verifier_options.cutoff_index = cutoff_index
        entries = evidence.entries
        if cutoff_index is not None:
            entries = [entry for entry in entries if entry.index <= cutoff_index]
        verified = verify_stream_lifecycle(entries, domain, verifier_options)
        self._assert_cutoff(verified, cutoff_index)
        context.budget.add_events(len(verified))
        events = [item.event for item in verified]
        events = _stitch_migration_history(domain, events, migration_results)
        result = _VerifiedHistory(
            events=events,
            checkpoint_witness_time=policy_result.checkpoint_witness_time,
            complete_through=evidence.checkpoint.tree_size,
            completeness_mode=evidence.completeness_mode or "full-scan",
            checkpoint=evidence.checkpoint_bytes or evidence.checkpoint,
            current_stream_events=verified,
            event_refs=_stitched_event_refs(
                self.parsed.lr, verified, migration_results
            ),
        )
        if use_cache:
            self._history_cache[cache_key] = result
        return result

    def _verify_prior_history(
        self,
        event: MigrationEvent,
        domain: str,
        trusted: JWK,
        context: _MigrationContext,
    ) -> MigrationVerificationResult:
        context.budget.activate()
        if event.new_log != self.parsed.lr:
            raise C2spTlogVerificationError(
                "MIGRATION new_lr does not match the current C2SP stream",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )
        try:
            previous_method, _ = parse_ledger_ref(event.previous_log)
            cutoff_method, _ = parse_ledger_ref(event.final_entry_ref)
        except ParseError as exc:
            raise C2spTlogVerificationError(
                "MIGRATION previous-log reference is invalid",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            ) from exc
        if previous_method != cutoff_method:
            raise C2spTlogVerificationError(
                "MIGRATION prev_ref must identify an entry in prev_lr",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )
        if context.depth >= context.budget.limits.max_depth:
            raise C2spTlogVerificationError(
                "MIGRATION recursion exceeds configured depth maximum "
                f"{context.budget.limits.max_depth}",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )
        if event.previous_log in context.budget.seen:
            raise C2spTlogVerificationError(
                f"MIGRATION cycle contains {event.previous_log!r}",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )
        factory = self._options.migration_reader_factory
        if factory is None:
            raise C2spTlogVerificationError(
                "MIGRATION requires a registered previous-log reader",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )
        context.budget.seen.add(event.previous_log)
        reader = factory(event.previous_log)
        if isinstance(reader, C2spTlogReader):
            try:
                previous = parse_c2sp_tlog_lr(event.previous_log)
                cutoff = parse_c2sp_tlog_lr(event.final_entry_ref)
            except C2spTlogError as exc:
                raise C2spTlogVerificationError(
                    "MIGRATION previous-log reference is invalid",
                    category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
                ) from exc
            if (
                previous.entry_index is not None
                or event.previous_log != previous.lr
                or cutoff.entry_index is None
                or cutoff.lr != previous.lr
                or event.final_entry_ref != _event_ref(previous.lr, cutoff.entry_index)
                or reader.parsed.lr != previous.lr
            ):
                raise C2spTlogVerificationError(
                    "MIGRATION prev_ref must exactly identify an entry in prev_lr",
                    category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
                )
            prior = reader._load_complete_history(
                domain,
                trusted,
                cutoff_index=cutoff.entry_index,
                migration_context=_MigrationContext(context.budget, context.depth + 1),
            )
        else:
            remaining_events = (
                context.budget.limits.max_history_events
                - context.budget.history_events
            )
            remaining_bytes = (
                context.budget.limits.max_response_bytes
                - context.budget.response_bytes
            )
            cutoff_history = reader.rebuild_history_through(
                domain,
                event.final_entry_ref,
                trusted,
                max_depth=context.budget.limits.max_depth - context.depth,
                max_events=remaining_events,
                max_response_bytes=remaining_bytes,
                seen_log_references=frozenset(context.budget.seen),
            )
            self._validate_predecessor_history(
                event, cutoff_history, context, remaining_events, remaining_bytes
            )
            context.budget.add_response(cutoff_history.response_bytes)
            context.budget.add_events(len(cutoff_history.events))
            prior = _VerifiedHistory(
                events=list(cutoff_history.events),
                checkpoint_witness_time=datetime.datetime.min.replace(
                    tzinfo=datetime.UTC
                ),
                complete_through=event.final_entry_ref,
                completeness_mode="verified-cutoff",
                checkpoint=None,
                event_refs=list(cutoff_history.event_refs),
            )
        snapshot = DomainLog(domain, cast(list[LogEvent], prior.events)).snapshot_at(
            datetime.datetime.max.replace(tzinfo=datetime.UTC)
        )
        issuance = next(
            (item for item in prior.events if isinstance(item, IssuanceEvent)), None
        )
        if (
            snapshot.historical_state != "ACTIVE"
            or snapshot.active_key is None
            or issuance is None
            or issuance.entity_key is None
            or issuance.governance_id != snapshot.governance_id
        ):
            raise C2spTlogVerificationError(
                "MIGRATION previous history must preserve an ACTIVE identity",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )
        if issuance.entity_key.thumbprint() != trusted.thumbprint():
            raise C2spTlogVerificationError(
                "MIGRATION entity-key continuity mismatch",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )
        return MigrationVerificationResult(
            issuance.entity_key,
            snapshot.active_key,
            list(prior.events),
            list(prior.event_refs),
        )

    @staticmethod
    def _validate_predecessor_history(
        migration: MigrationEvent,
        history: VerifiedCutoffHistory,
        context: _MigrationContext,
        max_events: int,
        max_response_bytes: int,
    ) -> None:
        if not isinstance(history, VerifiedCutoffHistory):
            raise C2spTlogVerificationError(
                "MIGRATION previous reader returned invalid cutoff evidence",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )
        if (
            not history.events
            or len(history.events) > max_events
            or len(history.event_refs) != len(history.events)
            or any(not isinstance(ref, str) or not ref for ref in history.event_refs)
            or history.event_refs[-1] != migration.final_entry_ref
            or type(history.response_bytes) is not int
            or history.response_bytes < 0
            or history.response_bytes > max_response_bytes
        ):
            raise C2spTlogVerificationError(
                "MIGRATION previous reader did not preserve the exact cutoff or bounds",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )
        migrations = [
            event for event in history.events if isinstance(event, MigrationEvent)
        ]
        if context.depth + 1 + len(migrations) > context.budget.limits.max_depth:
            raise C2spTlogVerificationError(
                "MIGRATION recursion exceeds configured depth maximum "
                f"{context.budget.limits.max_depth}",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )
        seen = set(context.budget.seen) - {migration.previous_log}
        current_log: str | None = None
        for event in migrations:
            if current_log is None:
                if event.previous_log in seen:
                    raise C2spTlogVerificationError(
                        f"MIGRATION cycle contains {event.previous_log!r}",
                        category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
                    )
                seen.add(event.previous_log)
            elif event.previous_log != current_log:
                raise C2spTlogVerificationError(
                    "MIGRATION previous history is not a continuous log handoff",
                    category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
                )
            if event.new_log in seen:
                raise C2spTlogVerificationError(
                    f"MIGRATION cycle contains {event.new_log!r}",
                    category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
                )
            seen.add(event.new_log)
            current_log = event.new_log
        if current_log is not None and current_log != migration.previous_log:
            raise C2spTlogVerificationError(
                "MIGRATION previous history does not end in prev_lr",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )
        context.budget.seen.update(seen)

    @staticmethod
    def _assert_cutoff(
        events: list[VerifiedLifecycleEvent], cutoff_index: int | None
    ) -> None:
        if cutoff_index is not None and (
            not events or events[-1].index != cutoff_index
        ):
            raise C2spTlogVerificationError(
                "MIGRATION prev_ref does not identify the final applied cutoff event",
                category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
            )

    def _enforce_append_only_consistency(
        self, evidence: StreamEvidence, witness_time: datetime.datetime
    ) -> None:
        """Require this checkpoint to extend the last trusted one for the origin.

        The complete scan has already been checked against the new checkpoint
        root, so we hold every leaf.  We therefore verify consistency directly:
        recompute the root of the previously trusted tree size from the leaf
        prefix and require it to equal the stored root.  A smaller tree
        (rollback) or a prefix-root mismatch (fork) fails closed; otherwise the
        trusted checkpoint advances.

        The check and the advance run under the store's per-origin lock (via
        ``verify_and_advance``) so concurrent verifications of the same origin
        cannot each accept a different forked extension of the same trusted
        checkpoint.
        """
        origin = self.parsed.origin
        new_size = evidence.checkpoint.tree_size
        candidate = TrustedCheckpoint(
            origin=origin,
            tree_size=new_size,
            root_hash=evidence.checkpoint.root_hash,
            witness_time=witness_time,
        )
        entries = sorted(evidence.entries, key=lambda e: e.index)

        def _verify(stored: TrustedCheckpoint | None) -> None:
            if stored is None:
                return
            if stored.tree_size > new_size:
                raise C2spCheckpointConsistencyError(
                    "C2SP checkpoint tree size regressed "
                    f"({new_size} < trusted {stored.tree_size}): rollback or fork",
                    category=C2spLifecycleErrorCategory.LOG_ROLLBACK,
                    trusted=stored,
                    observed=candidate,
                )
            if stored.tree_size == new_size and stored.root_hash != candidate.root_hash:
                raise C2spCheckpointConsistencyError(
                    "C2SP checkpoint is not consistent: different root at trusted size",
                    category=C2spLifecycleErrorCategory.LOG_FORK,
                    trusted=stored,
                    observed=candidate,
                )
            if stored.tree_size >= 1:
                prefix_root = merkle_root_from_entries(
                    [e.data for e in entries[: stored.tree_size]]
                )
                if prefix_root != stored.root_hash:
                    raise C2spCheckpointConsistencyError(
                        "C2SP checkpoint is not consistent with the trusted "
                        "checkpoint: the trusted tree is not a prefix (fork)",
                        category=C2spLifecycleErrorCategory.LOG_INCONSISTENT,
                        trusted=stored,
                        observed=candidate,
                    )

        self._options.checkpoint_store.verify_and_advance(candidate, _verify)

    def _unchained(self, origin: str) -> bool:
        if self._options.unchained is not None:
            return self._options.unchained
        return normalized_origin_policy(self._options.policy, origin).unchained

    def _verifier_options(
        self,
        parsed: ParsedC2spTlogLr,
        signer_key: JWK,
        checkpoint_witness_time: datetime.datetime,
    ) -> StreamVerifierOptions:
        return StreamVerifierOptions(
            context=self._context(parsed),
            unchained=self._unchained(parsed.origin),
            signer_key=signer_key,
            checkpoint_integration_time_ms=checkpoint_witness_time.timestamp() * 1000
            + self._options.max_clock_skew_ms,
        )

    def _checkpoint_is_stale(
        self, checkpoint_witness_time: datetime.datetime
    ) -> bool:
        freshness = self._options.checkpoint_freshness_ms
        return freshness is not None and (
            self._now_ms() - checkpoint_witness_time.timestamp() * 1000 > freshness
        )

    def _assert_fresh(self, checkpoint_witness_time: datetime.datetime) -> None:
        if self._options.checkpoint_freshness_ms is None:
            raise _log_error(
                "non-revocation verification requires checkpoint_freshness_ms"
            )
        if self._checkpoint_is_stale(checkpoint_witness_time):
            raise _log_error("C2SP checkpoint is too stale for non-revocation verification")

    def _context(self, parsed: ParsedC2spTlogLr | None = None) -> C2spEventContext:
        p = parsed or self.parsed
        return C2spEventContext(
            scope=p.scope,
            log_origin=p.origin,
            stream_id=p.stream_id,
            lr=self.lr,
        )

    @staticmethod
    def _now_ms() -> float:
        return time.time() * 1000


def _event_ref(lr: str, index: int) -> str:
    return f"{lr}@{index}"


def _stream_evidence_bytes(evidence: StreamEvidence) -> int:
    represented = len(evidence.checkpoint_bytes) + sum(
        len(entry.data) + 2 for entry in evidence.entries
    )
    return max(represented, evidence.response_bytes or 0)


def _stitched_event_refs(
    lr: str,
    events: list[VerifiedLifecycleEvent],
    migration_results: dict[int, MigrationVerificationResult],
) -> list[str]:
    current = [_event_ref(lr, item.index) for item in events]
    if not events or not isinstance(events[0].event, MigrationEvent):
        return current
    migration = migration_results.get(id(events[0].event))
    if (
        migration is None
        or len(migration.prior_event_refs) != len(migration.prior_events)
    ):
        raise C2spTlogVerificationError(
            "MIGRATION verification did not preserve prior-log event references",
            category=C2spLifecycleErrorCategory.INVALID_MIGRATION,
        )
    return [*migration.prior_event_refs, *current]


def _assert_complete_scan(evidence: StreamEvidence) -> None:
    entries = sorted(evidence.entries, key=lambda e: e.index)
    if len(entries) != evidence.checkpoint.tree_size:
        raise C2spTlogVerificationError(
            "complete C2SP scan length does not match checkpoint tree size",
            category=C2spLifecycleErrorCategory.INCOMPLETE_STREAM,
        )
    for index, entry in enumerate(entries):
        if entry.index != index:
            raise C2spTlogVerificationError(
                "complete C2SP scan must contain every index exactly once",
                category=C2spLifecycleErrorCategory.INCOMPLETE_STREAM,
            )
    root = merkle_root_from_entries([entry.data for entry in entries])
    if root != evidence.checkpoint.root_hash:
        raise C2spTlogVerificationError(
            "scanned C2SP entries do not match checkpoint root",
            category=C2spLifecycleErrorCategory.INVALID_EVIDENCE,
        )


def _stitch_migration_history(
    domain: str,
    events: list[AnyLogEvent],
    migration_results: dict[int, MigrationVerificationResult],
) -> list[AnyLogEvent]:
    if not events or not isinstance(events[0], MigrationEvent):
        return events
    migration_event = events[0]
    migration = migration_results.get(id(migration_event))
    if migration is None or not migration.prior_events:
        raise _log_error(
            "MIGRATION verification did not return complete prior-log history",
            C2spLifecycleErrorCategory.INVALID_MIGRATION,
        )
    if any(
        isinstance(prior_event, MigrationEvent)
        and prior_event.domain == migration_event.domain
        and prior_event.previous_log == migration_event.previous_log
        and prior_event.new_log == migration_event.new_log
        and prior_event.final_entry_ref == migration_event.final_entry_ref
        for prior_event in migration.prior_events
    ):
        raise _log_error(
            "MIGRATION prior-log history contains the inbound migration",
            C2spLifecycleErrorCategory.INVALID_MIGRATION,
        )
    prior_snapshot_at = max(event.timestamp for event in migration.prior_events)
    prior_snapshot = DomainLog(
        domain, cast(list[LogEvent], migration.prior_events)
    ).snapshot_at(prior_snapshot_at)
    if (
        prior_snapshot.historical_state != "ACTIVE"
        or prior_snapshot.active_key_thumbprint != migration.operational_key.thumbprint()
    ):
        raise _log_error(
            "MIGRATION prior-log history does not establish the recovered active key",
            C2spLifecycleErrorCategory.INVALID_MIGRATION,
        )
    prior_issuance = next(
        (event for event in migration.prior_events if isinstance(event, IssuanceEvent)),
        None,
    )
    if (
        prior_issuance is None
        or prior_issuance.entity_key is None
        or prior_issuance.entity_key.thumbprint() != migration.entity_key.thumbprint()
    ):
        raise _log_error(
            "MIGRATION prior-log history does not establish the recovered entity key",
            C2spLifecycleErrorCategory.INVALID_MIGRATION,
        )
    return [*migration.prior_events, *events]


def _as_any_event(event: LogEvent) -> AnyLogEvent:
    from ..models import (
        DelegationEvent,
        MigrationEvent,
        RetirementEvent,
    )

    if isinstance(
        event,
        (
            IssuanceEvent,
            KeyRotationEvent,
            RevocationEvent,
            RetirementEvent,
            MigrationEvent,
            DelegationEvent,
        ),
    ):
        return event
    raise C2spTlogVerificationError(
        f"{type(event).__name__} is not supported by c2sp-tlog version 1"
    )


class C2spTlogBinding(C2spTlogReader):
    """Reader plus the prepared-event operations, bound to this stream's lr.

    The generic write API is not implemented: appends go through the
    prepared-event flow and a deployment-specific submitter.
    """

    def prepare_event(
        self, event: AnyLogEvent, chain: prepared_mod.C2spChain | None = None
    ) -> prepared_mod.PreparedC2spTlogEvent:
        """Prepare *event* for signature collection, bound to this stream's lr."""
        return prepared_mod.prepare_event(event, self.parsed.lr, chain)

    def parse_prepared_event(
        self,
        data: bytes,
        context: prepared_mod.C2spVerificationContext | None = None,
    ) -> prepared_mod.PreparedC2spTlogEvent:
        """Parse prepared-event bytes and check they bind to this stream's lr."""
        return prepared_mod.parse_prepared_event(data, self.parsed.lr, context)

    def sign_prepared_event(
        self,
        prepared: prepared_mod.PreparedC2spTlogEvent,
        role: prepared_mod.C2spSignerRole,
        key_provider: KeyProviderT,
        context: prepared_mod.C2spVerificationContext | None = None,
        *,
        replace_existing: bool = False,
    ) -> prepared_mod.PreparedC2spTlogEvent:
        """Add the *role* signature to *prepared* using *key_provider*."""
        return prepared_mod.sign_prepared_event(
            prepared, role, key_provider, context, replace_existing=replace_existing
        )

    def entry_bytes(
        self,
        prepared: prepared_mod.PreparedC2spTlogEvent,
        context: prepared_mod.C2spVerificationContext | None = None,
    ) -> bytes:
        """Return the final canonical entry bytes for a fully signed *prepared*."""
        return prepared_mod.entry_bytes(prepared, context)

    def write_prepared_event(
        self,
        prepared: prepared_mod.PreparedC2spTlogEvent,
        *,
        submit: Callable[[bytes, str], int],
        idempotency_key: str,
        validate_chain: Callable[[prepared_mod.PreparedC2spTlogEvent], None]
        | None = None,
        context: prepared_mod.C2spVerificationContext | None = None,
    ) -> LogRef:
        """Submit *prepared* through *submit* and return its bound LogRef."""
        return prepared_mod.write_prepared_event(
            prepared,
            submit=submit,
            idempotency_key=idempotency_key,
            validate_chain=validate_chain,
            context=context,
        )


def _adapt_c2sp_error(exc: C2spTlogError) -> Exception:
    from ..enums import VerificationCode
    from ..exceptions import VerificationError

    category = (
        getattr(exc, "category", None)
        or C2spLifecycleErrorCategory.INVALID_EVIDENCE
    )
    category_value = (
        category.value
        if isinstance(category, C2spLifecycleErrorCategory)
        else str(category)
    )
    return VerificationError(
        VerificationCode.LOG_ERROR,
        "C2SP log verification failed: " + str(exc),
        transient=bool(getattr(exc, "transient", False)),
        category=category_value,
        cause=exc,
    )


def _log_error(
    message: str,
    category: C2spLifecycleErrorCategory | None = None,
    *,
    transient: bool = False,
    cause: BaseException | None = None,
) -> Exception:
    from ..enums import VerificationCode
    from ..exceptions import VerificationError

    return VerificationError(
        VerificationCode.LOG_ERROR,
        message,
        transient=transient,
        category=(category or C2spLifecycleErrorCategory.INVALID_EVIDENCE).value,
        cause=cause,
    )
