"""DNSid-managed C2SP trust selection tests."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path

import pytest

from dnsid._crypto import jwk_from_dict
from dnsid._utils import b64url_decode_strict
from dnsid.c2sp_tlog import (
    C2spResourceFetchGuarantees,
    C2spStreamBundleVerifierOptions,
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
    verify_c2sp_stream_bundle,
)
from dnsid.c2sp_tlog.managed_verification_registry import (
    _DEVELOPMENT_TRUST_PROFILE,
    _MANAGED_CATALOG,
    _PARTNERS_TRUST_PROFILE,
    _PRODUCTION_TRUST_PROFILE,
    _STAGING_TRUST_PROFILE,
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
# Signs dev bundles over the 4096-byte KMS limit (Identity-Digital/dnsid#3286).
_DEVELOPMENT_OVERFLOW_BUNDLE_KEY = "dnsid-stream-bundle+62f7f9fa+ATdOWF5P759HgvDod9mIC0r1nXhTtJ7x1Ws0fjTvqwDV"
_PRODUCTION_POLICY = b"""log log.dnsid.ai+f10a26bc+Aeo6u4o1XvQlcRczgY462ZdIGpm/ejBC2G3vSbyYYqqY
witness dnsid-witness-1 witness.dnsid.ai/w1+706fd4fb+BLqX21Sx9xG5+5vK7kSK5omcu9+2il20PLdfpOp8lQOJ
quorum dnsid-witness-1
"""
_PRODUCTION_BUNDLE_KEY = "dnsid-stream-bundle+2e77a3f1+AbKj/zrAfK04/NM07Zj7kxP2YXbM5neT8ym6juXC2PXG"
# Signs production bundles over the 4096-byte KMS limit (Identity-Digital/dnsid#3286).
_PRODUCTION_OVERFLOW_BUNDLE_KEY = "dnsid-stream-bundle+0f5a76a0+AXavEa0+EGj/qZFH4QuAOeomigSukspWQHC7PrVJa7pj"


class _Fetcher:
    def fetch_bounded(self, url: str, max_bytes: int) -> bytes:
        raise AssertionError("catalog construction must not fetch trust material")

    def security_guarantees(self) -> C2spResourceFetchGuarantees:
        return C2spResourceFetchGuarantees(True, True, True, True, True)


_STAGING_POLICY = b"""log log.stg.dnsid.ai+f6ad3bd8+ARl6baGOUzNIH2QvsnlqA8C71WM4SYecXE7eAwmytAsL
witness dnsid-witness-1 witness.stg.dnsid.ai/w1+11a84cde+BEKB6hwsWXOm+PMnS7/JvO4i6bazjzJ8ojECphOTB3gt
quorum dnsid-witness-1
"""
_STAGING_BUNDLE_KEY = "dnsid-stream-bundle+65c31b14+AXCMTPR4I/fqOgSHge4AEMp+1pWcflDqC1YEDaHDe3Ps"
# Signs staging bundles over the 4096-byte KMS limit (Identity-Digital/dnsid#3286).
_STAGING_OVERFLOW_BUNDLE_KEY = "dnsid-stream-bundle+cdd64875+ATu1SYXvRiZPBUzrUJAfKHeMH3eHr3T22jKez/C3Yl1m"
_PARTNERS_POLICY = b"""log log.partners.dnsid.ai+f0143e09+Ae5vrTVQUr0h2GKbeHq70ml37N+uVBsU4NpZD4qMqAu1
witness dnsid-witness-1 witness.partners.dnsid.ai/w1+a115eb67+BB0avWVeSelUBk2w8FtTbT+orf2i826q9VemA0jaXxg4
quorum dnsid-witness-1
"""
_PARTNERS_BUNDLE_KEY = "dnsid-stream-bundle+b1e0b597+AQt9ol4cfwPHxdH4NHNRidsAvU2bYE7KVItOlBG/bsaZ"
# Signs partner bundles over the 4096-byte KMS limit (Identity-Digital/dnsid#3286).
_PARTNERS_OVERFLOW_BUNDLE_KEY = "dnsid-stream-bundle+bc0d8136+AVfizbWWQD+s2N7OfpOeP7IaWF8nAeTqT4JpD03vKqc6"
# Live checkpoint captured on 2026-10-16, signed by the log and its witness.
_PARTNERS_CHECKPOINT = Path(__file__).parent / "vectors" / "c2sp-partners-checkpoint.txt"


def test_development_catalog_entry_is_exact_trust_profile() -> None:
    document = json.loads(_DEVELOPMENT_TRUST_PROFILE)
    assert document == {
        "version": 1,
        "scope": "public",
        "log_prefix": "https://log.dev.dnsid.ai",
        "tlog_policy": _DEVELOPMENT_POLICY.decode(),
        "bundle_verifier_keys": [_DEVELOPMENT_BUNDLE_KEY, _DEVELOPMENT_OVERFLOW_BUNDLE_KEY],
    }
    profile = parse_c2sp_tlog_trust_profile(_DEVELOPMENT_TRUST_PROFILE)
    assert profile.policy_document == _DEVELOPMENT_POLICY
    assert profile.bundle_verifier_keys == [
        parse_signed_note_verifier_key(_DEVELOPMENT_BUNDLE_KEY),
        parse_signed_note_verifier_key(_DEVELOPMENT_OVERFLOW_BUNDLE_KEY),
    ]


def test_production_catalog_entry_is_exact_trust_profile() -> None:
    document = json.loads(_PRODUCTION_TRUST_PROFILE)
    assert document == {
        "version": 1,
        "scope": "public",
        "log_prefix": "https://log.dnsid.ai",
        "tlog_policy": _PRODUCTION_POLICY.decode(),
        "bundle_verifier_keys": [_PRODUCTION_BUNDLE_KEY, _PRODUCTION_OVERFLOW_BUNDLE_KEY],
    }
    profile = parse_c2sp_tlog_trust_profile(_PRODUCTION_TRUST_PROFILE)
    assert profile.policy_document == _PRODUCTION_POLICY
    assert profile.bundle_verifier_keys == [
        parse_signed_note_verifier_key(_PRODUCTION_BUNDLE_KEY),
        parse_signed_note_verifier_key(_PRODUCTION_OVERFLOW_BUNDLE_KEY),
    ]


def test_partners_catalog_entry_is_exact_trust_profile() -> None:
    document = json.loads(_PARTNERS_TRUST_PROFILE)
    assert document == {
        "version": 1,
        "scope": "public",
        "log_prefix": "https://log.partners.dnsid.ai",
        "tlog_policy": _PARTNERS_POLICY.decode(),
        "bundle_verifier_keys": [_PARTNERS_BUNDLE_KEY, _PARTNERS_OVERFLOW_BUNDLE_KEY],
    }
    profile = parse_c2sp_tlog_trust_profile(_PARTNERS_TRUST_PROFILE)
    assert profile.policy_document == _PARTNERS_POLICY
    assert profile.bundle_verifier_keys == [
        parse_signed_note_verifier_key(_PARTNERS_BUNDLE_KEY),
        parse_signed_note_verifier_key(_PARTNERS_OVERFLOW_BUNDLE_KEY),
    ]


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
    assert checkpoint.tree_size == 172
    assert len(result.accepted_witness_timestamps) == 1


def test_partners_profile_verifies_partner_stream_bundle() -> None:
    # Reviewed service fixture from Identity-Digital/dnsid#2639, captured 2026-10-02.
    data = (Path(__file__).parent / "vectors" / "c2sp-partners-stream-bundle.json").read_bytes()
    bundle = json.loads(data)
    issuance = json.loads(b64url_decode_strict(bundle["events"][0]["entry"]))
    result = verify_c2sp_stream_bundle(
        data,
        C2spStreamBundleVerifierOptions(
            policy_bytes=_PARTNERS_POLICY,
            bundle_keys=[parse_signed_note_verifier_key(_PARTNERS_BUNDLE_KEY)],
            entity_key=jwk_from_dict(issuance["ek"]),
            checkpoint_freshness_ms=600_000,
            max_bundle_lifetime_ms=600_000,
            max_bundle_bytes=128 * 1024,
            max_events=16,
            now=lambda: bundle["expires"] - 60,
        ),
    )
    assert result.bundle_signer_kid == "dnsid-stream-bundle+b1e0b597"
    assert result.logged_state == "ACTIVE"
    assert len(result.events) == 1


@pytest.mark.parametrize(
    ("fixture", "kid", "events"),
    [
        ("c2sp-dev-stream-bundle-kms-key.json", "dnsid-stream-bundle+0c241174", 2),
        ("c2sp-dev-stream-bundle-overflow-key.json", "dnsid-stream-bundle+62f7f9fa", 3),
    ],
)
def test_development_profile_verifies_bundles_from_both_bundle_keys(fixture: str, kid: str, events: int) -> None:
    # Reviewed service fixtures from Identity-Digital/dnsid#3286, captured 2026-11-10.
    # The dev log signs a bundle of at most 4096 signed bytes with its KMS key and a
    # larger one with a secret-held key, so the pinned development profile must
    # accept both: a two-event stream signed by the KMS key and a three-event
    # stream (issuance, key rotation, revocation) signed by the secret-held key.
    profile = parse_c2sp_tlog_trust_profile(_DEVELOPMENT_TRUST_PROFILE)
    data = (Path(__file__).parent / "vectors" / fixture).read_bytes()
    bundle = json.loads(data)
    issuance = json.loads(b64url_decode_strict(bundle["events"][0]["entry"]))
    result = verify_c2sp_stream_bundle(
        data,
        C2spStreamBundleVerifierOptions(
            policy_bytes=profile.policy_document,
            bundle_keys=profile.bundle_verifier_keys,
            entity_key=jwk_from_dict(issuance["ek"]),
            checkpoint_freshness_ms=600_000,
            max_bundle_lifetime_ms=600_000,
            max_bundle_bytes=128 * 1024,
            max_events=16,
            now=lambda: bundle["expires"] - 60,
        ),
    )
    assert result.bundle_signer_kid == kid
    assert result.logged_state == "REVOKED"
    assert len(result.events) == events


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
    staging = registry.new_reader("c2sp-tlog:public:https://log.stg.dnsid.ai#EREREREREREREREREREREQ")

    for reader in (development, production, partners, staging):
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


def test_staging_catalog_entry_is_exact_trust_profile() -> None:
    document = json.loads(_STAGING_TRUST_PROFILE)
    assert document == {
        "version": 1,
        "scope": "public",
        "log_prefix": "https://log.stg.dnsid.ai",
        "tlog_policy": _STAGING_POLICY.decode(),
        "bundle_verifier_keys": [_STAGING_BUNDLE_KEY, _STAGING_OVERFLOW_BUNDLE_KEY],
    }
    profile = parse_c2sp_tlog_trust_profile(_STAGING_TRUST_PROFILE)
    assert profile.policy_document == _STAGING_POLICY
    assert profile.bundle_verifier_keys == [
        parse_signed_note_verifier_key(_STAGING_BUNDLE_KEY),
        parse_signed_note_verifier_key(_STAGING_OVERFLOW_BUNDLE_KEY),
    ]


@pytest.mark.parametrize(
    ("fixture", "kid", "state", "events"),
    [
        ("c2sp-staging-stream-bundle-kms-key.json", "dnsid-stream-bundle+65c31b14", "ACTIVE", 1),
        ("c2sp-staging-stream-bundle-overflow-key.json", "dnsid-stream-bundle+cdd64875", "REVOKED", 3),
    ],
)
def test_staging_profile_verifies_bundles_from_both_bundle_keys(
    fixture: str, kid: str, state: str, events: int
) -> None:
    # Reviewed service fixtures captured from log.stg.dnsid.ai on 2026-11-11
    # (Identity-Digital/dnsid#3286): a one-event stream small enough for the KMS
    # bundle key and a three-event stream (issuance, key rotation, revocation)
    # over the 4096-byte KMS limit, signed by the secret-held key.
    profile = parse_c2sp_tlog_trust_profile(_STAGING_TRUST_PROFILE)
    data = (Path(__file__).parent / "vectors" / fixture).read_bytes()
    bundle = json.loads(data)
    issuance = json.loads(b64url_decode_strict(bundle["events"][0]["entry"]))
    result = verify_c2sp_stream_bundle(
        data,
        C2spStreamBundleVerifierOptions(
            policy_bytes=profile.policy_document,
            bundle_keys=profile.bundle_verifier_keys,
            entity_key=jwk_from_dict(issuance["ek"]),
            checkpoint_freshness_ms=600_000,
            max_bundle_lifetime_ms=600_000,
            max_bundle_bytes=128 * 1024,
            max_events=16,
            now=lambda: bundle["expires"] - 60,
        ),
    )
    assert result.bundle_signer_kid == kid
    assert result.logged_state == state
    assert len(result.events) == events


def test_managed_bundle_key_ids_match_their_key_bytes() -> None:
    # Parsing checks only the key ID's length, so recompute each signed-note key ID
    # (the first four bytes of SHA-256 over name, newline, type byte and key) to
    # catch a key copied with the wrong ID before a log starts signing with it.
    for entry in _MANAGED_CATALOG:
        assert entry.trust_profile_document is not None
        keys = json.loads(entry.trust_profile_document)["bundle_verifier_keys"]
        assert keys, entry.log_prefix
        for key in keys:
            name, key_id, encoded = key.split("+", 2)
            computed = hashlib.sha256(name.encode() + b"\n" + base64.b64decode(encoded)).digest()[:4]
            assert computed.hex() == key_id, f"{entry.log_prefix}: {key}"
