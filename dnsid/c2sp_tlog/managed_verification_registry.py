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
    b'AeuT9PKyiewb9hkzygvki7UuOs5ly2kfY/C4Tfh7/ix0",\n'
    b'    "dnsid-stream-bundle+62f7f9fa+'
    b'ATdOWF5P759HgvDod9mIC0r1nXhTtJ7x1Ws0fjTvqwDV"\n  ]\n}'
)
_PRODUCTION_TRUST_PROFILE = (
    b'{\n  "version": 1,\n  "scope": "public",\n'
    b'  "log_prefix": "https://log.dnsid.ai",\n  "tlog_policy": "'
    b"log log.dnsid.ai+f10a26bc+Aeo6u4o1XvQlcRczgY462ZdIGpm/ejBC2G3vSbyYYqqY\\n"
    b"witness dnsid-witness-1 "
    b"witness.dnsid.ai/w1+706fd4fb+BLqX21Sx9xG5+5vK7kSK5omcu9+2il20PLdfpOp8lQOJ\\n"
    b'quorum dnsid-witness-1\\n",\n  "bundle_verifier_keys": [\n'
    b'    "dnsid-stream-bundle+2e77a3f1+'
    b'AbKj/zrAfK04/NM07Zj7kxP2YXbM5neT8ym6juXC2PXG",\n'
    b'    "dnsid-stream-bundle+0f5a76a0+AXavEa0+'
    b'EGj/qZFH4QuAOeomigSukspWQHC7PrVJa7pj"\n  ]\n}'
)

# Matches the reviewed service profile in Identity-Digital/dnsid#2639;
# the log's discovery endpoints are not trust anchors.
_PARTNERS_TRUST_PROFILE = (
    b'{\n  "version": 1,\n  "scope": "public",\n'
    b'  "log_prefix": "https://log.partners.dnsid.ai",\n  "tlog_policy": "'
    b"log log.partners.dnsid.ai+f0143e09+Ae5vrTVQUr0h2GKbeHq70ml37N+uVBsU4NpZD4qMqAu1\\n"
    b"witness dnsid-witness-1 "
    b"witness.partners.dnsid.ai/w1+a115eb67+BB0avWVeSelUBk2w8FtTbT+orf2i826q9VemA0jaXxg4\\n"
    b'quorum dnsid-witness-1\\n",\n  "bundle_verifier_keys": [\n'
    b'    "dnsid-stream-bundle+b1e0b597+'
    b'AQt9ol4cfwPHxdH4NHNRidsAvU2bYE7KVItOlBG/bsaZ",\n'
    b'    "dnsid-stream-bundle+bc0d8136+AVfizbWWQD+'
    b's2N7OfpOeP7IaWF8nAeTqT4JpD03vKqc6"\n  ]\n}'
)


# Matches the reviewed service profile internal/c2sptrust/profiles/staging.json in
# Identity-Digital/dnsid (its second bundle key from Identity-Digital/dnsid#3526);
# the log's discovery endpoints are not trust anchors.
_STAGING_TRUST_PROFILE = (
    b'{\n  "version": 1,\n  "scope": "public",\n'
    b'  "log_prefix": "https://log.stg.dnsid.ai",\n  "tlog_policy": "'
    b"log log.stg.dnsid.ai+f6ad3bd8+ARl6baGOUzNIH2QvsnlqA8C71WM4SYecXE7eAwmytAsL\\n"
    b"witness dnsid-witness-1 "
    b"witness.stg.dnsid.ai/w1+11a84cde+BEKB6hwsWXOm+PMnS7/JvO4i6bazjzJ8ojECphOTB3gt\\n"
    b'quorum dnsid-witness-1\\n",\n  "bundle_verifier_keys": [\n'
    b'    "dnsid-stream-bundle+65c31b14+'
    b'AXCMTPR4I/fqOgSHge4AEMp+1pWcflDqC1YEDaHDe3Ps",\n'
    b'    "dnsid-stream-bundle+cdd64875+'
    b'ATu1SYXvRiZPBUzrUJAfKHeMH3eHr3T22jKez/C3Yl1m"\n  ]\n}'
)


# Matches the reviewed service profile internal/c2sptrust/profiles/known-dev.json in
# Identity-Digital/dnsid; the log's discovery endpoints are not trust anchors.
_KNOWN_DEVELOPMENT_TRUST_PROFILE = (
    b'{\n  "version": 1,\n  "scope": "public",\n'
    b'  "log_prefix": "https://log.dev.knownsystems.ai",\n  "tlog_policy": "'
    b"log log.dev.knownsystems.ai+78742e4f+AWJIIC/ZPaSwAprXLHT+JZ7lbTipE3MciQOdUGqG1T3j\\n"
    b"witness dnsid-witness-1 "
    b"witness.dev.knownsystems.ai/w1+21be2f43+BLsio+pQhADB8grceyZnOVERcoq+V6oJuUNy/IEfhsgt\\n"
    b'quorum dnsid-witness-1\\n",\n  "bundle_verifier_keys": [\n'
    b'    "dnsid-stream-bundle+138e0d41+'
    b'AXy9jwvH7hY3LgjqoZn3GmNllKTj2TyNApRLKbt/2WSU",\n'
    b'    "dnsid-stream-bundle+ad87852b+'
    b'AWWyHhKGf9oKqaRCQfrk9kixjuz4fmhI5P08W5bsYxzj"\n  ]\n}'
)


# Matches the reviewed service profile internal/c2sptrust/profiles/known-staging.json in
# Identity-Digital/dnsid; the log's discovery endpoints are not trust anchors.
_KNOWN_STAGING_TRUST_PROFILE = (
    b'{\n  "version": 1,\n  "scope": "public",\n'
    b'  "log_prefix": "https://log.stg.knownsystems.ai",\n  "tlog_policy": "'
    b"log log.stg.knownsystems.ai+d3504618+AaUJP26XksZKcjmWHs7Cyq244q2efKUH1geUNb6bK5G7\\n"
    b"witness dnsid-witness-1 "
    b"witness.stg.knownsystems.ai/w1+e3954927+BA8QcWZ+kIuuakqhAbltJ1lFAYeuEqE98AYWyG9eKTil\\n"
    b'quorum dnsid-witness-1\\n",\n  "bundle_verifier_keys": [\n'
    b'    "dnsid-stream-bundle+85bbbf6c+'
    b'AQEr6kb1rP1ZUJxEUl5ai5KxD86uHDRhHoF9rGewVgvC",\n'
    b'    "dnsid-stream-bundle+64bf74b3+'
    b'Aa0M4XaiO7BzP4fn7gLnWOw570/ml9x8xnEiv5fUqIW1"\n  ]\n}'
)


# Matches the reviewed service profile internal/c2sptrust/profiles/known-production.json in
# Identity-Digital/dnsid; the log's discovery endpoints are not trust anchors.
_KNOWN_PRODUCTION_TRUST_PROFILE = (
    b'{\n  "version": 1,\n  "scope": "public",\n'
    b'  "log_prefix": "https://log.knownsystems.ai",\n  "tlog_policy": "'
    b"log log.knownsystems.ai+ffa9d1c9+Ad/NRlpkBsb9RjFstpUI2V38LF0G9DaJgHWtx5UtS6a7\\n"
    b"witness dnsid-witness-1 "
    b"witness.knownsystems.ai/w1+f726713e+BPq3DkSLKz0bMwDnwhwb9yhsGKT/0g0iPKZYekuumLfV\\n"
    b'quorum dnsid-witness-1\\n",\n  "bundle_verifier_keys": [\n'
    b'    "dnsid-stream-bundle+4c5de6cf+'
    b'AeoiHt6HX3fniAPFeNMerJ52HKAlfLxbwFnxvyVM8GPj",\n'
    b'    "dnsid-stream-bundle+4296adc5+'
    b'AX8gHt0vQT0mICUKU2svFWcdcIhcQmGHYuR2kk/EsXex"\n  ]\n}'
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
    _ManagedTrustEntry(
        "public",
        "https://log.partners.dnsid.ai",
        trust_profile_document=_PARTNERS_TRUST_PROFILE,
    ),
    _ManagedTrustEntry(
        "public",
        "https://log.stg.dnsid.ai",
        trust_profile_document=_STAGING_TRUST_PROFILE,
    ),
    _ManagedTrustEntry(
        "public",
        "https://log.dev.knownsystems.ai",
        trust_profile_document=_KNOWN_DEVELOPMENT_TRUST_PROFILE,
    ),
    _ManagedTrustEntry(
        "public",
        "https://log.stg.knownsystems.ai",
        trust_profile_document=_KNOWN_STAGING_TRUST_PROFILE,
    ),
    _ManagedTrustEntry(
        "public",
        "https://log.knownsystems.ai",
        trust_profile_document=_KNOWN_PRODUCTION_TRUST_PROFILE,
    ),
)


def create_dnsid_managed_verification_registry(
    options: DnsidManagedVerificationOptions | None = None,
) -> LogRegistry:
    """Create a registry for reviewed DNSid-managed trust roots.

    Calling this separately named factory is an explicit application trust
    decision; the generic factory never selects these roots implicitly. Trust
    snapshots are bundled with the SDK and selected only for an exact canonical
    ``(scope, log_prefix)`` pair. The catalog covers the development,
    production, partner (``https://log.partners.dnsid.ai``), and staging
    (``https://log.stg.dnsid.ai``) logs, and the Known development
    (``https://log.dev.knownsystems.ai``), staging
    (``https://log.stg.knownsystems.ai``), and production
    (``https://log.knownsystems.ai``) logs, each preferring signed stream
    bundles with safe raw-scan fallback.
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
    if options.resource_fetcher is None and isinstance(fetcher, SafeC2spResourceFetcher):
        registry._owned_resources.append(fetcher)

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
