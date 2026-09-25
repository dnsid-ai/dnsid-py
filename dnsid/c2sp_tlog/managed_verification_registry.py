"""Opt-in verification setup for DNSid-managed DNSid logs."""

from __future__ import annotations

from dataclasses import dataclass

from ..exceptions import ArgumentError
from ..interfaces import LogReader
from ..registry import LogRegistry
from .checkpoint_store import CheckpointStore, InMemoryCheckpointStore
from .errors import C2spTlogParseError, C2spTlogVerificationError
from .lr import checkpoint_origin, parse_c2sp_tlog_lr
from .policy import parse_c2sp_policy_file
from .reader import C2spTlogReader
from .resource_fetcher import C2spBoundedResourceFetcher, SafeC2spResourceFetcher
from .trust_profile import parse_c2sp_tlog_trust_profile
from .verification_registry import (
    C2spTlogVerificationOptions,
    create_c2sp_tlog_verification_registry,
)

_MANAGED_FRESHNESS_MS = 10 * 60 * 1000
_DEVELOPMENT_TRUST_PROFILE = (
    b'{\n  "version": 1,\n  "scope": "public",\n'
    b'  "log_prefix": "https://log.dev.dnsid.ai",\n  "tlog_policy": "'
    b"log log.dev.dnsid.ai+cad12acd+Afnd3sdzfp8nCXzDQchrnWn9QOox5AglR147bURESRqu\\n"
    b"witness dnsid-witness-1 "
    b"witness.dev.dnsid.ai/w1+50822ded+BAH9KuulelD3yZBDTneG46gKZY+OWwdUPBmLmq/YjOkO\\n"
    b'quorum dnsid-witness-1\\n",\n  "bundle_verifier_keys": [\n'
    b'    "dnsid-stream-bundle+0c241174+'
    b'AeuT9PKyiewb9hkzygvki7UuOs5ly2kfY/C4Tfh7/ix0"\n  ]\n}'
)
_PRODUCTION_TRUST_PROFILE = (
    b'{\n  "version": 1,\n  "scope": "public",\n'
    b'  "log_prefix": "https://log.dnsid.ai",\n  "tlog_policy": "'
    b"log log.dnsid.ai+c4683585+AWZYC4OLE9KeRnpaI9xaHWwHUKoxgp/24ukzgVYlDwIt\\n"
    b"witness dnsid-witness-1 "
    b"witness.dnsid.ai/w1+b5ea211e+BH0nGTkjF4tYpkefsQhHNg0YagPvQ6H96Y3UBbXo7a/b\\n"
    b'quorum dnsid-witness-1\\n",\n  "bundle_verifier_keys": [\n'
    b'    "dnsid-stream-bundle+ee2b26d2+'
    b'AWGLBe4LhJKumyDpH8VJ0vyATB081i1HseVeETu4TONR"\n  ]\n}'
)


@dataclass
class DnsidManagedVerificationOptions:
    """Shared infrastructure for managed DNSid log verification.

    Trust roots, freshness, resource limits, and bundle preference are fixed by
    the embedded managed catalog. Callers needing different trust use
    :func:`create_c2sp_tlog_verification_registry`.
    """

    resource_fetcher: C2spBoundedResourceFetcher | None = None
    trusted_checkpoint_store: CheckpointStore | None = None


@dataclass(frozen=True)
class _ManagedTrustEntry:
    scope: str
    log_prefix: str
    trust_profile_document: bytes | None = None
    policy_document: bytes | None = None


_MANAGED_CATALOG = (
    _ManagedTrustEntry(
        "public",
        "https://log.dev.dnsid.ai",
        trust_profile_document=_DEVELOPMENT_TRUST_PROFILE,
    ),
    _ManagedTrustEntry(
        "public",
        "https://log.dnsid.ai",
        trust_profile_document=_PRODUCTION_TRUST_PROFILE,
    ),
)


def create_dnsid_managed_verification_registry(
    options: DnsidManagedVerificationOptions | None = None,
) -> LogRegistry:
    """Create a registry for reviewed DNSid-managed trust roots.

    Calling this separately named factory is an explicit application trust
    decision; the generic factory never selects these roots implicitly. Trust
    snapshots are bundled with the SDK and selected only for an exact canonical
    ``(scope, log_prefix)`` pair. Development and production prefer signed
    stream bundles with safe raw-scan fallback.
    """
    if options is None:
        options = DnsidManagedVerificationOptions()
    if not isinstance(options, DnsidManagedVerificationOptions):
        raise ArgumentError("options must be DnsidManagedVerificationOptions")
    return _create_dnsid_managed_verification_registry(options, _MANAGED_CATALOG)


def _create_dnsid_managed_verification_registry(
    options: DnsidManagedVerificationOptions,
    catalog: tuple[_ManagedTrustEntry, ...],
) -> LogRegistry:
    fetcher = (
        options.resource_fetcher
        if options.resource_fetcher is not None
        else SafeC2spResourceFetcher()
    )
    store = (
        options.trusted_checkpoint_store
        if options.trusted_checkpoint_store is not None
        else InMemoryCheckpointStore()
    )
    registries: dict[tuple[str, str], LogRegistry] = {}

    for entry in catalog:
        reference = parse_c2sp_tlog_lr(
            f"c2sp-tlog:{entry.scope}:{entry.log_prefix}#managed-catalog"
        )
        selector = (reference.scope, reference.log_prefix)
        if selector in registries:
            raise C2spTlogParseError("duplicate DNSid managed trust selector")

        if entry.trust_profile_document is not None and entry.policy_document is None:
            profile = parse_c2sp_tlog_trust_profile(entry.trust_profile_document)
            if (profile.scope, profile.log_prefix) != selector:
                raise C2spTlogParseError("DNSid managed trust profile selector mismatch")
            verification_options = C2spTlogVerificationOptions(
                trust_profile=profile,
                resource_fetcher=fetcher,
                trusted_checkpoint_store=store,
                checkpoint_freshness_ms=_MANAGED_FRESHNESS_MS,
                max_clock_skew_ms=0,
                max_bundle_lifetime_ms=_MANAGED_FRESHNESS_MS,
            )
        elif entry.policy_document is not None and entry.trust_profile_document is None:
            try:
                policy = parse_c2sp_policy_file(entry.policy_document.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise C2spTlogParseError("DNSid managed policy is not UTF-8") from exc
            if set(policy.origins) != {checkpoint_origin(reference.log_prefix)}:
                raise C2spTlogParseError("DNSid managed policy selector mismatch")
            verification_options = C2spTlogVerificationOptions(
                policy_document=entry.policy_document,
                resource_fetcher=fetcher,
                trusted_checkpoint_store=store,
                checkpoint_freshness_ms=_MANAGED_FRESHNESS_MS,
                max_clock_skew_ms=0,
            )
        else:
            raise C2spTlogParseError(
                "DNSid managed catalog entry must contain exactly one trust document"
            )
        registries[selector] = create_c2sp_tlog_verification_registry(verification_options)

    registry = LogRegistry()

    def reader(lr: str) -> LogReader:
        reference = parse_c2sp_tlog_lr(lr)
        selected = registries.get((reference.scope, reference.log_prefix))
        if selected is None:
            raise C2spTlogParseError("unknown DNSid managed trust selector")
        bound = selected.new_reader(lr)
        if not isinstance(bound, C2spTlogReader):
            raise C2spTlogVerificationError(
                "managed c2sp-tlog registry returned an incompatible reader"
            )
        bound._options.migration_reader_factory = registry.new_reader
        return bound

    registry.register("c2sp-tlog", reader)
    return registry


__all__ = [
    "DnsidManagedVerificationOptions",
    "create_dnsid_managed_verification_registry",
]
