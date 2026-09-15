"""DNSid C2SP trust-profile parsing and registry binding."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from dnsid.c2sp_tlog import (
    C2spTlogParseError,
    C2spTlogVerificationError,
    C2spTlogVerificationOptions,
    ScanStreamSource,
    create_c2sp_tlog_verification_registry,
    parse_c2sp_tlog_trust_profile,
)
from dnsid.c2sp_tlog.stream_bundle import _FetchedStreamBundleSource
from dnsid.exceptions import ArgumentError

_POLICY = (
    "log log.example+3db4ee08+AcqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58\n"
    "witness primary witness.example+da76602f+BG56HN0psLeP0Tr0xVmP7/TvKpcWbjym8uT7/M2AUFvx\n"
    "quorum primary\n"
)
_KEYS = [
    "dnsid-stream-bundle+dfa43feb+AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "dnsid-stream-bundle+85e03385+AQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
]


def _verifier_key(name: str, payload: bytes) -> str:
    key_id = hashlib.sha256(name.encode() + b"\n" + payload).hexdigest()[:8]
    return f"{name}+{key_id}+{base64.b64encode(payload).decode()}"


def _document(**overrides: object) -> bytes:
    profile: dict[str, object] = {
        "version": 1,
        "scope": "public",
        "log_prefix": "https://log.example",
        "tlog_policy": _POLICY,
        "bundle_verifier_keys": _KEYS,
    }
    profile.update(overrides)
    return json.dumps(profile).encode()


def test_profile_accepts_rotation_keys_and_constrains_registry() -> None:
    profile = parse_c2sp_tlog_trust_profile(_document())
    assert len(profile.bundle_verifier_keys) == 2
    registry = create_c2sp_tlog_verification_registry(
        C2spTlogVerificationOptions(
            trust_profile=profile, max_bundle_lifetime_ms=300_000
        )
    )
    reader = registry.new_reader("c2sp-tlog:public:https://log.example#stream")
    assert isinstance(reader._source, _FetchedStreamBundleSource)
    assert isinstance(reader._source._fallback, ScanStreamSource)
    with pytest.raises(C2spTlogVerificationError, match="trust profile"):
        registry.new_reader("c2sp-tlog:public:https://other.example#stream")
    with pytest.raises(ArgumentError, match="exactly one"):
        create_c2sp_tlog_verification_registry(
            C2spTlogVerificationOptions(
                trust_profile=profile,
                policy_document=profile.policy_document,
                max_bundle_lifetime_ms=300_000,
            )
        )
    with pytest.raises(ArgumentError, match="mutually exclusive"):
        create_c2sp_tlog_verification_registry(
            C2spTlogVerificationOptions(
                trust_profile=profile,
                bundle_verifier_keys=[],
                max_bundle_lifetime_ms=300_000,
            )
        )
    with pytest.raises(ArgumentError, match="max_bundle_lifetime_ms"):
        create_c2sp_tlog_verification_registry(
            C2spTlogVerificationOptions(trust_profile=profile)
        )


@pytest.mark.parametrize(
    "document",
    [
        _document(extra=True),
        _document(version=2),
        _document(log_prefix="https://log.example/"),
        _document(log_prefix="https://other.example"),
        _document(bundle_verifier_keys=[_KEYS[0], _KEYS[0]]),
        _document(bundle_verifier_keys=[_KEYS[0].replace("dnsid-stream-bundle", "other")]),
        _document(bundle_verifier_keys=[_KEYS[0].replace("dfa43feb", "00000000")]),
        _document(
            tlog_policy=_POLICY.replace(
                _POLICY.splitlines()[0],
                "log " + _verifier_key("log.example", base64.b64decode(_KEYS[0].split("+", 2)[2])),
            ),
            bundle_verifier_keys=[_KEYS[0]],
        ),
        (
            b'{"version":1,"version":1,"scope":"public",'
            b'"log_prefix":"https://log.example","tlog_policy":"x",'
            b'"bundle_verifier_keys":[]}'
        ),
    ],
)
def test_profile_rejects_invalid_documents(document: bytes) -> None:
    with pytest.raises((C2spTlogParseError, C2spTlogVerificationError)):
        parse_c2sp_tlog_trust_profile(document)
