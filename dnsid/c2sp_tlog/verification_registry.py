"""Safe convenience setup for ordinary c2sp-tlog verification."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from ..exceptions import ArgumentError
from ..registry import LogRegistry
from .checkpoint_store import CheckpointStore, InMemoryCheckpointStore
from .errors import C2spTlogParseError, C2spTlogVerificationError
from .lr import parse_c2sp_tlog_lr
from .policy import normalized_origin_policy, parse_c2sp_policy_file
from .reader import (
    C2spMigrationVerificationLimits,
    C2spTlogReader,
    C2spTlogReaderOptions,
)
from .resource_fetcher import (
    C2spBoundedResourceFetcher,
    SafeC2spResourceFetcher,
    fetch_bounded_bytes,
    validate_resource_fetcher_capabilities,
)
from .signed_note import SignedNoteKey
from .stream_source import C2spScanLimits
from .trust_profile import (
    C2spTlogTrustProfile,
    validate_c2sp_bundle_verifier_keys,
    validate_c2sp_tlog_trust_profile,
)

_DEFAULT_MAX_POLICY_BYTES = 1_048_576
_DEFAULT_MAX_BUNDLE_LIFETIME_MS = 300_000
_DEFAULT_MAX_STREAM_BUNDLE_BYTES = 8 * 1024 * 1024
_DEFAULT_MAX_STREAM_BUNDLE_EVENTS = 10_000


@dataclass
class C2spTlogVerificationOptions:
    """Configure :func:`create_c2sp_tlog_verification_registry`.

    Exactly one of :attr:`trust_profile`, :attr:`policy_document`, and
    :attr:`policy_url` is required. A policy URL is independently trusted caller
    configuration and is never inferred from an identity record or log prefix.

    ``resource_fetcher`` is shared by policy and standard C2SP reads. Custom
    fetchers must implement the bounded-fetch and explicit security-capability
    contract. The built-in fetcher requires HTTPS and HTTP 200, rejects
    redirects and unsafe destinations, pins connections to validated DNS
    results, bounds decoded bytes during reads, and uses finite deadlines.

    A trust profile or direct ``bundle_verifier_keys`` enables verified
    per-domain stream bundles. Unavailable endpoints fall back to the bounded
    complete scanner. A valid newer bundle without a separate consistency proof
    uses a complete scan to verify both checkpoint roots.
    ``require_stream_bundle`` disables both fallbacks. A positive
    ``max_bundle_lifetime_ms`` is required whenever bundle keys are configured;
    bundle byte and event limits retain finite defaults.

    ``migration_limits`` has finite defaults for recursive depth, cumulative
    history events, and cumulative response bytes. Predecessor references are
    dispatched through the returned registry; additional registered methods
    must implement the method-neutral verified-cutoff contract.
    ``checkpoint_freshness_ms``
    intentionally has no default. Non-revocation therefore fails closed unless
    the application chooses a positive maximum age. The default checkpoint
    store is process-lifetime only; inject durable storage when rollback
    protection must survive restarts.
    """

    policy_document: bytes | None = None
    policy_url: str | None = None
    trust_profile: C2spTlogTrustProfile | None = None
    bundle_verifier_keys: list[SignedNoteKey] | None = None
    resource_fetcher: C2spBoundedResourceFetcher | None = None
    scan_limits: C2spScanLimits | None = None
    migration_limits: C2spMigrationVerificationLimits | None = None
    trusted_checkpoint_store: CheckpointStore | None = None
    max_policy_bytes: int = _DEFAULT_MAX_POLICY_BYTES
    checkpoint_freshness_ms: int | None = None
    max_clock_skew_ms: int = 0
    max_bundle_lifetime_ms: int | None = None
    max_stream_bundle_bytes: int = _DEFAULT_MAX_STREAM_BUNDLE_BYTES
    max_stream_bundle_events: int = _DEFAULT_MAX_STREAM_BUNDLE_EVENTS
    require_stream_bundle: bool = False


def create_c2sp_tlog_verification_registry(
    options: C2spTlogVerificationOptions,
) -> LogRegistry:
    """Create a ready-to-inject registry for standard c2sp-tlog verification."""
    if not isinstance(options, C2spTlogVerificationOptions):
        raise ArgumentError("options must be C2spTlogVerificationOptions")
    has_profile = options.trust_profile is not None
    has_document = options.policy_document is not None
    has_url = options.policy_url is not None
    if sum((has_profile, has_document, has_url)) != 1:
        raise ArgumentError(
            "exactly one c2sp-tlog trust_profile, policy_document, or policy_url is required"
        )
    if has_profile:
        assert options.trust_profile is not None
        validate_c2sp_tlog_trust_profile(options.trust_profile)
        if options.bundle_verifier_keys is not None:
            raise ArgumentError(
                "c2sp-tlog trust_profile is mutually exclusive with direct "
                "bundle_verifier_keys"
            )
    if options.bundle_verifier_keys is not None:
        _validate_direct_bundle_verifier_keys(options.bundle_verifier_keys)
    bundle_keys = (
        options.trust_profile.bundle_verifier_keys
        if options.trust_profile is not None
        else options.bundle_verifier_keys or []
    )
    has_bundle_trust = bool(bundle_keys)
    _positive_integer(options.max_policy_bytes, "max_policy_bytes")
    if options.max_bundle_lifetime_ms is not None:
        _positive_integer(options.max_bundle_lifetime_ms, "max_bundle_lifetime_ms")
    if has_bundle_trust and options.max_bundle_lifetime_ms is None:
        raise ArgumentError(
            "c2sp-tlog bundle verifier keys require max_bundle_lifetime_ms"
        )
    _positive_integer(options.max_stream_bundle_bytes, "max_stream_bundle_bytes")
    _positive_integer(options.max_stream_bundle_events, "max_stream_bundle_events")
    if type(options.require_stream_bundle) is not bool:
        raise ArgumentError("c2sp-tlog require_stream_bundle must be a boolean")
    if options.require_stream_bundle and not has_bundle_trust:
        raise ArgumentError(
            "c2sp-tlog require_stream_bundle requires bundle verifier keys"
        )
    _non_negative_integer(options.max_clock_skew_ms, "max_clock_skew_ms")
    if options.checkpoint_freshness_ms is not None:
        _positive_integer(options.checkpoint_freshness_ms, "checkpoint_freshness_ms")
    if options.scan_limits is not None and not isinstance(options.scan_limits, C2spScanLimits):
        raise ArgumentError("c2sp-tlog scan_limits must be C2spScanLimits")
    if options.migration_limits is not None and not isinstance(
        options.migration_limits, C2spMigrationVerificationLimits
    ):
        raise ArgumentError(
            "c2sp-tlog migration_limits must be C2spMigrationVerificationLimits"
        )

    fetcher: C2spBoundedResourceFetcher = (
        options.resource_fetcher
        if options.resource_fetcher is not None
        else SafeC2spResourceFetcher()
    )
    # The registry can later construct a public reader even when the policy was
    # supplied as bytes, so reject an insufficient custom fetcher at creation.
    validate_resource_fetcher_capabilities(fetcher)

    if has_profile:
        assert options.trust_profile is not None
        document = options.trust_profile.policy_document
    elif has_url:
        assert options.policy_url is not None
        _validate_policy_url(options.policy_url)
        document = fetch_bounded_bytes(fetcher, options.policy_url, options.max_policy_bytes)
    else:
        assert options.policy_document is not None
        document = options.policy_document
        if not isinstance(document, bytes):
            raise ArgumentError("c2sp-tlog policy_document must be bytes")

    try:
        policy_text = document.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise C2spTlogVerificationError("c2sp-tlog policy document must be UTF-8") from exc
    policy = parse_c2sp_policy_file(policy_text)
    if options.bundle_verifier_keys:
        checkpoint_keys = []
        for origin in policy.origins:
            origin_policy = normalized_origin_policy(policy, origin)
            checkpoint_keys.extend(origin_policy.log_keys)
            checkpoint_keys.extend(origin_policy.witness_keys)
        _validate_direct_bundle_verifier_keys(bundle_keys, checkpoint_keys)
    checkpoint_store = (
        options.trusted_checkpoint_store
        if options.trusted_checkpoint_store is not None
        else InMemoryCheckpointStore()
    )
    max_bundle_lifetime_ms = (
        options.max_bundle_lifetime_ms or _DEFAULT_MAX_BUNDLE_LIFETIME_MS
    )
    reader_options = C2spTlogReaderOptions(
        policy=policy,
        transport=fetcher,
        scan_limits=options.scan_limits,
        migration_limits=(
            options.migration_limits or C2spMigrationVerificationLimits()
        ),
        checkpoint_store=checkpoint_store,
        checkpoint_freshness_ms=options.checkpoint_freshness_ms,
        max_clock_skew_ms=options.max_clock_skew_ms,
        bundle_policy_document=document if has_bundle_trust else None,
        bundle_keys=list(bundle_keys),
        bundle_checkpoint_freshness_ms=(
            options.checkpoint_freshness_ms or max_bundle_lifetime_ms
        ),
        max_bundle_lifetime_ms=max_bundle_lifetime_ms,
        max_bundle_bytes=options.max_stream_bundle_bytes,
        max_bundle_events=options.max_stream_bundle_events,
        require_stream_bundle=options.require_stream_bundle,
    )
    registry = LogRegistry()
    trusted_scope = options.trust_profile.scope if options.trust_profile else None
    trusted_log_prefix = options.trust_profile.log_prefix if options.trust_profile else None

    def reader(lr: str) -> C2spTlogReader:
        if trusted_scope is not None:
            reference = parse_c2sp_tlog_lr(lr)
            if reference.scope != trusted_scope or reference.log_prefix != trusted_log_prefix:
                raise C2spTlogVerificationError(
                    "c2sp-tlog reference is not accepted by the trust profile"
                )
        return C2spTlogReader(lr, reader_options)

    registry.register("c2sp-tlog", reader)
    reader_options.migration_reader_factory = registry.new_reader
    return registry


def _validate_direct_bundle_verifier_keys(
    keys: list[SignedNoteKey], checkpoint_keys: list[SignedNoteKey] | None = None
) -> None:
    try:
        validate_c2sp_bundle_verifier_keys(keys, checkpoint_keys)
    except C2spTlogParseError as exc:
        raise ArgumentError(f"invalid c2sp-tlog bundle_verifier_keys: {exc}") from exc


def _validate_policy_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        parsed.port
    except (TypeError, ValueError) as exc:
        raise ArgumentError("c2sp-tlog policy_url must be a valid HTTPS URL") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ArgumentError(
            "c2sp-tlog policy_url must be an absolute HTTPS URL without userinfo or fragment"
        )


def _positive_integer(value: object, name: str) -> int:
    if type(value) is not int or value < 1:
        raise ArgumentError(f"c2sp-tlog {name} must be a positive integer")
    return value


def _non_negative_integer(value: object, name: str) -> int:
    if type(value) is not int or value < 0:
        raise ArgumentError(f"c2sp-tlog {name} must be a non-negative integer")
    return value


__all__ = [
    "C2spTlogVerificationOptions",
    "create_c2sp_tlog_verification_registry",
]
