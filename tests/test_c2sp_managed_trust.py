"""DNSid-managed C2SP trust selection tests."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from dnsid.c2sp_tlog import (
    C2spResourceFetchGuarantees,
    C2spTlogError,
    C2spTlogReader,
    DnsidManagedVerificationOptions,
    InMemoryCheckpointStore,
    ScanStreamSource,
    create_dnsid_managed_verification_registry,
    enforce_checkpoint_policy,
    parse_c2sp_policy_file,
    parse_c2sp_tlog_trust_profile,
    parse_checkpoint,
    parse_signed_note_verifier_key,
)
from dnsid.c2sp_tlog.managed_verification_registry import (
    _DEVELOPMENT_TRUST_PROFILE,
    _MANAGED_CATALOG,
    _PARTNERS_TRUST_PROFILE,
    _PRODUCTION_TRUST_PROFILE,
    _create_dnsid_managed_verification_registry,
    _ManagedTrustEntry,
)
from dnsid.c2sp_tlog.stream_bundle import _FetchedStreamBundleSource

_VECTOR = Path(__file__).parent / "vectors" / "c2sp-managed-trust-selection.json"
_DEVELOPMENT_POLICY = b"""log log.dev.dnsid.ai+cad12acd+Afnd3sdzfp8nCXzDQchrnWn9QOox5AglR147bURESRqu
witness dnsid-witness-1 witness.dev.dnsid.ai/w1+50822ded+BAH9KuulelD3yZBDTneG46gKZY+OWwdUPBmLmq/YjOkO
quorum dnsid-witness-1
"""
_DEVELOPMENT_BUNDLE_KEY = "dnsid-stream-bundle+0c241174+AeuT9PKyiewb9hkzygvki7UuOs5ly2kfY/C4Tfh7/ix0"
_PRODUCTION_POLICY = b"""log log.dnsid.ai+f10a26bc+Aeo6u4o1XvQlcRczgY462ZdIGpm/ejBC2G3vSbyYYqqY
witness dnsid-witness-1 witness.dnsid.ai/w1+706fd4fb+BLqX21Sx9xG5+5vK7kSK5omcu9+2il20PLdfpOp8lQOJ
quorum dnsid-witness-1
"""
_PRODUCTION_BUNDLE_KEY = "dnsid-stream-bundle+2e77a3f1+AbKj/zrAfK04/NM07Zj7kxP2YXbM5neT8ym6juXC2PXG"


class _Fetcher:
    def fetch_bounded(self, url: str, max_bytes: int) -> bytes:
        raise AssertionError("catalog construction must not fetch trust material")

    def security_guarantees(self) -> C2spResourceFetchGuarantees:
        return C2spResourceFetchGuarantees(True, True, True, True, True)


_PARTNERS_POLICY = b"""log log.partners.dnsid.ai+52d6a7c3+ASsAuEkXpM63Qh2yh0q7DvueHqITfWGvcpWCOQfaDz5m
witness dnsid-witness-1 witness.partners.dnsid.ai/w1+a115eb67+BB0avWVeSelUBk2w8FtTbT+orf2i826q9VemA0jaXxg4
quorum dnsid-witness-1
"""
_PARTNERS_BUNDLE_KEY = "dnsid-stream-bundle+b12677d8+AWOB3PQPuFoGK66bqsFRcNh4n4q2DaAcauBijHymUUWH"
# The size-1 checkpoint https://log.partners.dnsid.ai served on 2026-09-28.
_PARTNERS_CHECKPOINT = Path(__file__).parent / "vectors" / "c2sp-partners-checkpoint-size1.txt"


def test_development_catalog_entry_is_exact_trust_profile() -> None:
    document = json.loads(_DEVELOPMENT_TRUST_PROFILE)
    assert document == {
        "version": 1,
        "scope": "public",
        "log_prefix": "https://log.dev.dnsid.ai",
        "tlog_policy": _DEVELOPMENT_POLICY.decode(),
        "bundle_verifier_keys": [_DEVELOPMENT_BUNDLE_KEY],
    }
    profile = parse_c2sp_tlog_trust_profile(_DEVELOPMENT_TRUST_PROFILE)
    assert profile.policy_document == _DEVELOPMENT_POLICY
    assert profile.bundle_verifier_keys == [parse_signed_note_verifier_key(_DEVELOPMENT_BUNDLE_KEY)]


def test_production_catalog_entry_is_exact_trust_profile() -> None:
    document = json.loads(_PRODUCTION_TRUST_PROFILE)
    assert document == {
        "version": 1,
        "scope": "public",
        "log_prefix": "https://log.dnsid.ai",
        "tlog_policy": _PRODUCTION_POLICY.decode(),
        "bundle_verifier_keys": [_PRODUCTION_BUNDLE_KEY],
    }
    profile = parse_c2sp_tlog_trust_profile(_PRODUCTION_TRUST_PROFILE)
    assert profile.policy_document == _PRODUCTION_POLICY
    assert profile.bundle_verifier_keys == [parse_signed_note_verifier_key(_PRODUCTION_BUNDLE_KEY)]


def test_partners_catalog_entry_is_exact_trust_profile() -> None:
    document = json.loads(_PARTNERS_TRUST_PROFILE)
    assert document == {
        "version": 1,
        "scope": "public",
        "log_prefix": "https://log.partners.dnsid.ai",
        "tlog_policy": _PARTNERS_POLICY.decode(),
        "bundle_verifier_keys": [_PARTNERS_BUNDLE_KEY],
    }
    profile = parse_c2sp_tlog_trust_profile(_PARTNERS_TRUST_PROFILE)
    assert profile.policy_document == _PARTNERS_POLICY
    assert profile.bundle_verifier_keys == [parse_signed_note_verifier_key(_PARTNERS_BUNDLE_KEY)]


def test_partners_policy_verifies_partner_log_checkpoint() -> None:
    # The pinned keys must be the ones the partner log and its witness sign with.
    checkpoint = parse_checkpoint(_PARTNERS_CHECKPOINT.read_text())
    result = enforce_checkpoint_policy(
        checkpoint,
        "log.partners.dnsid.ai",
        parse_c2sp_policy_file(_PARTNERS_POLICY.decode()),
        "public",
        now_ms=time.time() * 1000,
    )
    assert checkpoint.tree_size == 1
    assert len(result.accepted_witness_timestamps) == 1


def test_managed_registry_implements_selection_vectors() -> None:
    registry = create_dnsid_managed_verification_registry()

    for case in json.loads(_VECTOR.read_text())["cases"]:
        if not case["expected"]["accepted"]:
            with pytest.raises(C2spTlogError, match="managed|prefix|stream id"):
                registry.new_reader(case["lr"])
            continue
        reader = registry.new_reader(case["lr"])
        assert isinstance(reader, C2spTlogReader)
        assert isinstance(reader._source, _FetchedStreamBundleSource) == (
            case["expected"]["trustMode"] == "trust-profile"
        )


def test_managed_registry_shares_infrastructure_and_fixed_defaults() -> None:
    fetcher = _Fetcher()
    store = InMemoryCheckpointStore()
    registry = create_dnsid_managed_verification_registry(
        DnsidManagedVerificationOptions(fetcher, store)
    )
    development = registry.new_reader(
        "c2sp-tlog:public:https://log.dev.dnsid.ai#EREREREREREREREREREREQ"
    )
    production = registry.new_reader("c2sp-tlog:public:https://log.dnsid.ai#EREREREREREREREREREREQ")
    partners = registry.new_reader(
        "c2sp-tlog:public:https://log.partners.dnsid.ai#EREREREREREREREREREREQ"
    )

    for reader in (development, production, partners):
        assert reader._options.checkpoint_store is store
        assert reader._options.checkpoint_freshness_ms == 600_000
        assert reader._options.max_clock_skew_ms == 0
        assert isinstance(reader._source, _FetchedStreamBundleSource)
        assert reader._source._fetcher is fetcher
        assert isinstance(reader._source._fallback, ScanStreamSource)
        assert reader._source._fallback._transport is fetcher
        assert reader._source._checkpoint_store is store
        assert reader._source._checkpoint_freshness_ms == 600_000
        assert reader._source._max_bundle_lifetime_ms == 600_000


@pytest.mark.parametrize(
    "catalog",
    [
        (_MANAGED_CATALOG[0], _MANAGED_CATALOG[0]),
        (
            _ManagedTrustEntry(
                "public",
                "https://log.dnsid.ai",
                trust_profile_document=_DEVELOPMENT_TRUST_PROFILE,
            ),
        ),
        (
            _ManagedTrustEntry(
                "public",
                "https://log.dev.dnsid.ai",
                policy_document=_PRODUCTION_POLICY,
            ),
        ),
        (
            _ManagedTrustEntry(
                "public",
                "https://log.dev.dnsid.ai",
                trust_profile_document=_DEVELOPMENT_TRUST_PROFILE,
                policy_document=_PRODUCTION_POLICY,
            ),
        ),
    ],
)
def test_managed_registry_rejects_invalid_catalog(catalog) -> None:
    with pytest.raises(C2spTlogError):
        _create_dnsid_managed_verification_registry(
            DnsidManagedVerificationOptions(_Fetcher()), catalog
        )
