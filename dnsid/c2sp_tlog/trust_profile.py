"""Independently distributed trust profiles for one exact C2SP log."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .canonical import parse_json_no_duplicate_members
from .errors import C2spTlogParseError
from .lr import parse_c2sp_tlog_lr
from .policy import normalized_origin_policy, parse_c2sp_policy_file
from .signed_note import SignedNoteKey, parse_signed_note_verifier_key

_MEMBERS = {
    "version",
    "scope",
    "log_prefix",
    "tlog_policy",
    "bundle_verifier_keys",
}


@dataclass
class C2spTlogTrustProfile:
    """Trusted policy and bundle signers bound to one exact log."""

    version: int
    scope: str
    log_prefix: str
    policy_document: bytes
    bundle_verifier_keys: list[SignedNoteKey]


def parse_c2sp_tlog_trust_profile(data: bytes) -> C2spTlogTrustProfile:
    """Parse and validate a ``dnsid-c2sp-tlog-trust-profile@v1`` document."""
    value = parse_json_no_duplicate_members(data)
    if not isinstance(value, dict) or set(value) != _MEMBERS:
        raise C2spTlogParseError("c2sp-tlog trust profile has unsupported or missing members")
    if (
        type(value["version"]) is not int
        or value["version"] != 1
        or not isinstance(value["scope"], str)
        or not isinstance(value["log_prefix"], str)
        or not isinstance(value["tlog_policy"], str)
        or not isinstance(value["bundle_verifier_keys"], list)
    ):
        raise C2spTlogParseError("invalid c2sp-tlog trust profile")
    reference = parse_c2sp_tlog_lr(
        f"c2sp-tlog:{value['scope']}:{value['log_prefix']}#trust-profile"
    )
    try:
        policy_document = value["tlog_policy"].encode("utf-8")
    except UnicodeEncodeError as exc:
        raise C2spTlogParseError("c2sp-tlog trust profile policy is not UTF-8") from exc
    key_strings = value["bundle_verifier_keys"]
    if not key_strings or any(
        not isinstance(key, str) or not key or key != key.strip() for key in key_strings
    ):
        raise C2spTlogParseError("c2sp-tlog trust profile requires bundle verifier keys")
    if len(set(key_strings)) != len(key_strings):
        raise C2spTlogParseError("c2sp-tlog trust profile bundle verifier keys must be distinct")
    keys = [parse_signed_note_verifier_key(key) for key in key_strings]
    validate_c2sp_bundle_verifier_keys(keys, required_name="dnsid-stream-bundle")
    profile = C2spTlogTrustProfile(
        version=1,
        scope=reference.scope,
        log_prefix=reference.log_prefix,
        policy_document=policy_document,
        bundle_verifier_keys=keys,
    )
    validate_c2sp_tlog_trust_profile(profile)
    return profile


def validate_c2sp_tlog_trust_profile(profile: C2spTlogTrustProfile) -> None:
    """Validate a parsed or directly constructed trust profile."""
    if (
        not isinstance(profile, C2spTlogTrustProfile)
        or type(profile.version) is not int
        or profile.version != 1
        or not isinstance(profile.scope, str)
        or not isinstance(profile.log_prefix, str)
        or not isinstance(profile.policy_document, bytes)
        or not isinstance(profile.bundle_verifier_keys, list)
        or not profile.bundle_verifier_keys
    ):
        raise C2spTlogParseError("invalid c2sp-tlog trust profile")
    reference = parse_c2sp_tlog_lr(f"c2sp-tlog:{profile.scope}:{profile.log_prefix}#trust-profile")
    try:
        policy = parse_c2sp_policy_file(profile.policy_document.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise C2spTlogParseError("c2sp-tlog trust profile policy is not UTF-8") from exc
    checkpoint = normalized_origin_policy(policy, reference.origin)
    validate_c2sp_bundle_verifier_keys(
        profile.bundle_verifier_keys,
        [*checkpoint.log_keys, *checkpoint.witness_keys],
        required_name="dnsid-stream-bundle",
    )


def validate_c2sp_bundle_verifier_keys(
    keys: list[SignedNoteKey],
    checkpoint_keys: list[SignedNoteKey] | None = None,
    *,
    required_name: str | None = None,
) -> None:
    """Validate independently trusted stream-bundle signer keys."""
    if not isinstance(keys, list):
        raise C2spTlogParseError("c2sp-tlog bundle verifier keys must be a list")
    key_ids: set[tuple[str, bytes]] = set()
    public_keys: set[bytes] = set()
    checkpoint_public_keys = {key.key_bytes for key in checkpoint_keys or []}
    for key in keys:
        _validate_bundle_key(key, required_name)
        assert key.key_id is not None
        identity = (key.name, key.key_id)
        if identity in key_ids or key.key_bytes in public_keys:
            raise C2spTlogParseError(
                "c2sp-tlog bundle verifier keys must have distinct public keys and key IDs"
            )
        if key.key_bytes in checkpoint_public_keys:
            raise C2spTlogParseError(
                "c2sp-tlog bundle signer must be independent of checkpoint policy keys"
            )
        key_ids.add(identity)
        public_keys.add(key.key_bytes)


def _validate_bundle_key(key: SignedNoteKey, required_name: str | None) -> None:
    if (
        not isinstance(key, SignedNoteKey)
        or not isinstance(key.name, str)
        or not key.name
        or (required_name is not None and key.name != required_name)
        or key.kind != "ed25519"
        or not isinstance(key.key_bytes, bytes)
        or len(key.key_bytes) != 32
        or not isinstance(key.key_id, bytes)
        or len(key.key_id) != 4
        or key.signature_type != b"\x01"
    ):
        raise C2spTlogParseError("invalid c2sp-tlog bundle verifier key")
    expected = hashlib.sha256(
        key.name.encode() + b"\n" + key.signature_type + key.key_bytes
    ).digest()[:4]
    if key.key_id != expected:
        raise C2spTlogParseError("invalid c2sp-tlog bundle verifier key hash")


__all__ = [
    "C2spTlogTrustProfile",
    "parse_c2sp_tlog_trust_profile",
    "validate_c2sp_bundle_verifier_keys",
]
