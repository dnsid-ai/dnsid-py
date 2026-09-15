"""Identity Digital-managed C2SP trust selection tests."""

from __future__ import annotations

import json
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
    parse_c2sp_tlog_trust_profile,
    parse_signed_note_verifier_key,
)
from dnsid.c2sp_tlog.managed_verification_registry import (
    _DEVELOPMENT_TRUST_PROFILE,
    _MANAGED_CATALOG,
    _PRODUCTION_TRUST_PROFILE,
    _create_dnsid_managed_verification_registry,
    _ManagedTrustEntry,
)
from dnsid.c2sp_tlog.stream_bundle import _FetchedStreamBundleSource

_VECTOR = Path(__file__).parent / "vectors" / "c2sp-managed-trust-selection.json"
_PRODUCTION_POLICY = b"""log log.dnsid.ai+c4683585+AWZYC4OLE9KeRnpaI9xaHWwHUKoxgp/24ukzgVYlDwIt
witness dnsid-witness-1 witness.dnsid.ai/w1+b5ea211e+BH0nGTkjF4tYpkefsQhHNg0YagPvQ6H96Y3UBbXo7a/b
quorum dnsid-witness-1
"""
_PRODUCTION_BUNDLE_KEY = "dnsid-stream-bundle+ee2b26d2+AWGLBe4LhJKumyDpH8VJ0vyATB081i1HseVeETu4TONR"


class _Fetcher:
    def fetch_bounded(self, url: str, max_bytes: int) -> bytes:
        raise AssertionError("catalog construction must not fetch trust material")

    def security_guarantees(self) -> C2spResourceFetchGuarantees:
        return C2spResourceFetchGuarantees(True, True, True, True, True)


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
        "c2sp-tlog:public:https://log.dnsid.dev#EREREREREREREREREREREQ"
    )
    production = registry.new_reader("c2sp-tlog:public:https://log.dnsid.ai#EREREREREREREREREREREQ")

    for reader in (development, production):
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
                "https://log.dnsid.dev",
                policy_document=_PRODUCTION_POLICY,
            ),
        ),
        (
            _ManagedTrustEntry(
                "public",
                "https://log.dnsid.dev",
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
