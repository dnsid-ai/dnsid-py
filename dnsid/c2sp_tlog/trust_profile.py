"""Independently distributed trust profiles for one exact C2SP log."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .canonical import _MAX_SAFE_INT, parse_json_no_duplicate_members
from .errors import C2spTlogError, C2spTlogParseError
from .lr import parse_c2sp_tlog_lr
from .policy import (
    C2spTlogEpochPolicy,
    C2spTlogPolicy,
    normalized_origin_policy,
    parse_c2sp_policy_file,
)
from .signed_note import SignedNoteKey, parse_signed_note_verifier_key

#: The original trust-profile format: one top-level policy and its bundle keys.
C2SP_TLOG_TRUST_PROFILE_VERSION_SINGLE = 1
#: The epoch format: complete trust epochs for one log, rotated together.
C2SP_TLOG_TRUST_PROFILE_VERSION_EPOCHS = 2

_MEMBERS = {
    "version",
    "scope",
    "log_prefix",
    "tlog_policy",
    "bundle_verifier_keys",
}
_EPOCH_PROFILE_MEMBERS = {"version", "scope", "log_prefix", "epochs"}
_EPOCH_REQUIRED_MEMBERS = {"id", "tlog_policy", "bundle_verifier_keys"}
_EPOCH_MEMBERS = _EPOCH_REQUIRED_MEMBERS | {"min_tree_size", "max_tree_size"}
_MAX_EPOCHS = 8
_EPOCH_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_BUNDLE_KEY_NAME = "dnsid-stream-bundle"


@dataclass
class C2spTlogTrustEpoch:
    """One complete trust epoch: a single-log policy and its bundle signers.

    ``policy_document`` must be byte-identical to the tlog-policy document the
    epoch's log server renders, because stream bundles bind its SHA-256 as
    ``policy_hash``. ``min_tree_size`` and ``max_tree_size`` are inclusive
    checkpoint tree-size bounds from 1 to 2^53-1; ``None`` leaves that side
    open.
    """

    id: str
    policy_document: bytes
    bundle_verifier_keys: list[SignedNoteKey]
    min_tree_size: int | None = None
    max_tree_size: int | None = None


@dataclass
class C2spTlogTrustProfile:
    """Trusted policy and bundle signers bound to one exact log.

    Version 1 carries ``policy_document`` and ``bundle_verifier_keys``.
    Version 2 leaves both empty and carries ``epochs`` instead: every epoch is
    a complete trust for the same log, and a checkpoint or bundle is accepted
    only when it satisfies one epoch completely.
    """

    version: int
    scope: str
    log_prefix: str
    policy_document: bytes = b""
    bundle_verifier_keys: list[SignedNoteKey] = field(default_factory=list)
    epochs: list[C2spTlogTrustEpoch] = field(default_factory=list)

    def trust_epochs(self) -> list[C2spTlogTrustEpoch]:
        """Return the validated trust epochs in profile order.

        A version 1 profile yields one epoch with an empty ``id`` and no
        tree-size bounds.

        Raises:
            C2spTlogError: If the profile is invalid.
        """
        validate_c2sp_tlog_trust_profile(self)
        if self.version == C2SP_TLOG_TRUST_PROFILE_VERSION_SINGLE:
            return [
                C2spTlogTrustEpoch(
                    id="",
                    policy_document=self.policy_document,
                    bundle_verifier_keys=list(self.bundle_verifier_keys),
                )
            ]
        return [_copy_epoch(epoch) for epoch in self.epochs]


def parse_c2sp_tlog_trust_profile(data: bytes) -> C2spTlogTrustProfile:
    """Parse and validate a DNSid C2SP trust-profile document.

    ``"version": 1`` is the original single-policy format. ``"version": 2``
    carries 1 to 8 ``epochs`` and must not contain the top-level
    ``tlog_policy`` or ``bundle_verifier_keys``, even empty.

    Raises:
        C2spTlogParseError: If the document is not a valid trust profile.
    """
    # No trust-profile member is fractional, so float and NaN/Infinity tokens
    # are rejected from the raw text; that alone keeps 5.0 and 5e0 out.
    value = parse_json_no_duplicate_members(data, integers_only=True)
    if (
        isinstance(value, dict)
        and type(value.get("version")) is int
        and value["version"] == C2SP_TLOG_TRUST_PROFILE_VERSION_EPOCHS
    ):
        return _parse_epoch_profile(value)
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
        isinstance(profile, C2spTlogTrustProfile)
        and type(profile.version) is int
        and profile.version == C2SP_TLOG_TRUST_PROFILE_VERSION_EPOCHS
    ):
        _validate_epoch_profile(profile)
        return
    if (
        not isinstance(profile, C2spTlogTrustProfile)
        or type(profile.version) is not int
        or profile.version != 1
        or not isinstance(profile.scope, str)
        or not isinstance(profile.log_prefix, str)
        or not isinstance(profile.policy_document, bytes)
        or not isinstance(profile.bundle_verifier_keys, list)
        or not profile.bundle_verifier_keys
        or profile.epochs
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


def c2sp_tlog_trust_profile_policy(profile: C2spTlogTrustProfile) -> C2spTlogPolicy:
    """Return the checkpoint policy a validated trust profile defines.

    Version 1 yields its parsed ``tlog_policy``. Version 2 yields an epoch
    policy (see :func:`create_c2sp_tlog_epoch_policy`).

    Raises:
        C2spTlogError: If the profile is invalid.
    """
    validate_c2sp_tlog_trust_profile(profile)
    if profile.version == C2SP_TLOG_TRUST_PROFILE_VERSION_EPOCHS:
        return create_c2sp_tlog_epoch_policy(profile.epochs)
    return parse_c2sp_policy_file(profile.policy_document.decode("utf-8"))


def create_c2sp_tlog_epoch_policy(epochs: list[C2spTlogTrustEpoch]) -> C2spTlogPolicy:
    """Build a checkpoint policy that accepts exactly one complete trust epoch.

    Every epoch must name one log origin, so trusted checkpoint state, which
    is keyed by origin, carries across epochs. A checkpoint is accepted only
    when one epoch's log signature, tree-size bounds and witness quorum all
    pass; signatures are never combined across epochs.

    Raises:
        C2spTlogParseError: If the epochs are invalid or ambiguous.
    """
    validate_c2sp_tlog_trust_epochs(epochs)
    return C2spTlogPolicy(
        origins={},
        epochs=[
            C2spTlogEpochPolicy(
                id=epoch.id,
                policy=_parse_epoch_policy_document(epoch.policy_document),
                min_tree_size=epoch.min_tree_size,
                max_tree_size=epoch.max_tree_size,
            )
            for epoch in epochs
        ],
    )


def validate_c2sp_tlog_trust_epochs(
    epochs: list[C2spTlogTrustEpoch], origin: str | None = None
) -> None:
    """Validate a verifier-side trust epoch set.

    Each epoch needs exactly one ``log`` key (named for the origin), a valid
    witness policy, independent ``dnsid-stream-bundle`` keys and in-range
    bounds. Across epochs, ids must be distinct, every epoch must name the same
    origin (*origin* when given), and no two epochs may share both a bundle key
    ID and a policy document, which would make bundle selection ambiguous.

    Raises:
        C2spTlogParseError: If the epoch set is invalid.
    """
    if not isinstance(epochs, list) or not epochs:
        raise C2spTlogParseError("c2sp-tlog trust epoch set is empty")
    seen_ids: set[str] = set()
    selections: dict[tuple[bytes, str], str] = {}
    expected_origin = origin
    for epoch in epochs:
        epoch_origin = _validate_trust_epoch(epoch, expected_origin)
        if expected_origin is None:
            expected_origin = epoch_origin
        if epoch.id in seen_ids:
            raise C2spTlogParseError("c2sp-tlog trust epoch ids must be distinct")
        seen_ids.add(epoch.id)
        for key in epoch.bundle_verifier_keys:
            assert key.key_id is not None
            selection = (epoch.policy_document, f"{key.name}+{key.key_id.hex()}")
            if selection in selections:
                raise C2spTlogParseError(
                    f"c2sp-tlog trust epochs {selections[selection]!r} and "
                    f"{epoch.id!r} share a bundle key ID and policy, so bundle "
                    "selection is ambiguous"
                )
            selections[selection] = epoch.id


def _validate_trust_epoch(epoch: C2spTlogTrustEpoch, origin: str | None) -> str:
    if (
        not isinstance(epoch, C2spTlogTrustEpoch)
        or not isinstance(epoch.id, str)
        or not isinstance(epoch.policy_document, bytes)
        or not isinstance(epoch.bundle_verifier_keys, list)
        or not epoch.bundle_verifier_keys
    ):
        raise C2spTlogParseError("invalid c2sp-tlog trust epoch")
    for bound in (epoch.min_tree_size, epoch.max_tree_size):
        if bound is not None and (
            type(bound) is not int or not 1 <= bound <= _MAX_SAFE_INT
        ):
            raise C2spTlogParseError(
                "c2sp-tlog trust epoch tree-size bounds must be integers from 1 to "
                "2^53-1; omit a bound to leave it open"
            )
    if (
        epoch.min_tree_size is not None
        and epoch.max_tree_size is not None
        and epoch.min_tree_size > epoch.max_tree_size
    ):
        raise C2spTlogParseError(
            "c2sp-tlog trust epoch min_tree_size exceeds max_tree_size"
        )
    policy = _parse_epoch_policy_document(epoch.policy_document)
    origins = list(policy.origins)
    if len(origins) != 1 or (origin is not None and origins[0] != origin):
        raise C2spTlogParseError(
            "c2sp-tlog trust epoch policy does not match the log origin"
        )
    try:
        checkpoint = normalized_origin_policy(policy, origins[0])
    except C2spTlogError as exc:
        raise C2spTlogParseError(f"invalid c2sp-tlog trust epoch policy: {exc}") from exc
    if len(checkpoint.log_keys) != 1:
        raise C2spTlogParseError(
            "c2sp-tlog trust epoch policy must contain exactly one log key"
        )
    for key in [*checkpoint.log_keys, *checkpoint.witness_keys]:
        _require_key_hash(key)
    try:
        validate_c2sp_bundle_verifier_keys(
            epoch.bundle_verifier_keys,
            [*checkpoint.log_keys, *checkpoint.witness_keys],
            required_name=_BUNDLE_KEY_NAME,
        )
    except C2spTlogError as exc:
        raise C2spTlogParseError(f"invalid c2sp-tlog trust epoch: {exc}") from exc
    return origins[0]


def _require_key_hash(key: SignedNoteKey) -> None:
    signature_type = key.signature_type or b"\x01"
    expected = hashlib.sha256(
        key.name.encode() + b"\n" + signature_type + key.key_bytes
    ).digest()[:4]
    if key.key_id != expected:
        raise C2spTlogParseError(
            "c2sp-tlog trust epoch policy keys need a matching key hash"
        )


def _parse_epoch_policy_document(document: bytes) -> C2spTlogPolicy:
    try:
        return parse_c2sp_policy_file(document.decode("utf-8", errors="strict"))
    except UnicodeDecodeError as exc:
        raise C2spTlogParseError("c2sp-tlog trust epoch policy is not UTF-8") from exc
    except C2spTlogError as exc:
        raise C2spTlogParseError(f"invalid c2sp-tlog trust epoch policy: {exc}") from exc


def _validate_epoch_profile(profile: C2spTlogTrustProfile) -> None:
    if (
        not isinstance(profile.scope, str)
        or not isinstance(profile.log_prefix, str)
        or not isinstance(profile.epochs, list)
    ):
        raise C2spTlogParseError("invalid c2sp-tlog trust profile")
    if profile.policy_document != b"" or profile.bundle_verifier_keys != []:
        raise C2spTlogParseError(
            "c2sp-tlog trust profile version 2 must carry its policies and "
            "bundle keys in epochs"
        )
    if not 1 <= len(profile.epochs) <= _MAX_EPOCHS:
        raise C2spTlogParseError(
            f"c2sp-tlog trust profile needs between 1 and {_MAX_EPOCHS} epochs"
        )
    for epoch in profile.epochs:
        if not isinstance(epoch, C2spTlogTrustEpoch) or not isinstance(epoch.id, str) or (
            not _EPOCH_ID_RE.fullmatch(epoch.id)
        ):
            raise C2spTlogParseError(
                "c2sp-tlog trust profile epoch id must be 1 to 64 characters of "
                "A-Z, a-z, 0-9, '.', '_' or '-'"
            )
    try:
        reference = parse_c2sp_tlog_lr(
            f"c2sp-tlog:{profile.scope}:{profile.log_prefix}#trust-profile"
        )
    except C2spTlogError as exc:
        raise C2spTlogParseError(
            f"invalid c2sp-tlog trust profile scope or log prefix: {exc}"
        ) from exc
    validate_c2sp_tlog_trust_epochs(profile.epochs, reference.origin)


def _parse_epoch_profile(value: dict[str, object]) -> C2spTlogTrustProfile:
    if set(value) != _EPOCH_PROFILE_MEMBERS:
        raise C2spTlogParseError(
            "c2sp-tlog trust profile version 2 has unsupported or missing members"
        )
    scope = value["scope"]
    log_prefix = value["log_prefix"]
    raw_epochs = value["epochs"]
    if (
        not isinstance(scope, str)
        or not isinstance(log_prefix, str)
        or not isinstance(raw_epochs, list)
    ):
        raise C2spTlogParseError("invalid c2sp-tlog trust profile")
    if not 1 <= len(raw_epochs) <= _MAX_EPOCHS:
        raise C2spTlogParseError(
            f"c2sp-tlog trust profile needs between 1 and {_MAX_EPOCHS} epochs"
        )
    epochs = [_parse_profile_epoch(raw) for raw in raw_epochs]
    profile = C2spTlogTrustProfile(
        version=C2SP_TLOG_TRUST_PROFILE_VERSION_EPOCHS,
        scope=scope,
        log_prefix=log_prefix,
        epochs=epochs,
    )
    _validate_epoch_profile(profile)
    reference = parse_c2sp_tlog_lr(f"c2sp-tlog:{scope}:{log_prefix}#trust-profile")
    profile.scope = reference.scope
    profile.log_prefix = reference.log_prefix
    return profile


def _parse_profile_epoch(raw: object) -> C2spTlogTrustEpoch:
    if (
        not isinstance(raw, dict)
        or not _EPOCH_REQUIRED_MEMBERS <= set(raw)
        or not set(raw) <= _EPOCH_MEMBERS
    ):
        raise C2spTlogParseError(
            "c2sp-tlog trust profile epoch has unsupported or missing members"
        )
    epoch_id = raw["id"]
    policy_text = raw["tlog_policy"]
    key_strings = raw["bundle_verifier_keys"]
    if (
        not isinstance(epoch_id, str)
        or not isinstance(policy_text, str)
        or not isinstance(key_strings, list)
    ):
        raise C2spTlogParseError("invalid c2sp-tlog trust profile epoch")
    try:
        policy_document = policy_text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise C2spTlogParseError("c2sp-tlog trust epoch policy is not UTF-8") from exc
    if not key_strings or any(
        not isinstance(key, str) or not key or key != key.strip() for key in key_strings
    ):
        raise C2spTlogParseError("c2sp-tlog trust epoch requires bundle verifier keys")
    if len(set(key_strings)) != len(key_strings):
        raise C2spTlogParseError("c2sp-tlog trust epoch bundle verifier keys must be distinct")
    keys = [parse_signed_note_verifier_key(key) for key in key_strings]
    return C2spTlogTrustEpoch(
        id=epoch_id,
        policy_document=policy_document,
        bundle_verifier_keys=keys,
        min_tree_size=_parse_tree_size_bound(raw.get("min_tree_size")),
        max_tree_size=_parse_tree_size_bound(raw.get("max_tree_size")),
    )


def _parse_tree_size_bound(value: object) -> int | None:
    # A bound is lexical: a number token matching ^[1-9][0-9]*$ and at most
    # 2^53-1. The parser already rejected fraction, exponent and NaN/Infinity
    # tokens, so an int here came from -?(0|[1-9][0-9]*); requiring an exact
    # int (JSON true/false decode as bool, a subclass of int) of at least 1
    # leaves exactly ^[1-9][0-9]*$. Strings such as "5" are not ints.
    if value is None:
        return None
    if type(value) is not int or not 1 <= value <= _MAX_SAFE_INT:
        raise C2spTlogParseError(
            "c2sp-tlog trust epoch tree-size bounds must be integers from 1 to "
            "2^53-1; omit a bound to leave it open"
        )
    return value


def _copy_epoch(epoch: C2spTlogTrustEpoch) -> C2spTlogTrustEpoch:
    return C2spTlogTrustEpoch(
        id=epoch.id,
        policy_document=epoch.policy_document,
        bundle_verifier_keys=list(epoch.bundle_verifier_keys),
        min_tree_size=epoch.min_tree_size,
        max_tree_size=epoch.max_tree_size,
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
    "C2SP_TLOG_TRUST_PROFILE_VERSION_EPOCHS",
    "C2SP_TLOG_TRUST_PROFILE_VERSION_SINGLE",
    "C2spTlogTrustEpoch",
    "C2spTlogTrustProfile",
    "c2sp_tlog_trust_profile_policy",
    "create_c2sp_tlog_epoch_policy",
    "parse_c2sp_tlog_trust_profile",
    "validate_c2sp_bundle_verifier_keys",
    "validate_c2sp_tlog_trust_epochs",
]
