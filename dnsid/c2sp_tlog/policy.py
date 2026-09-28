"""C2SP checkpoint trust policy: log keys, witness quorums, enforcement."""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field

from .checkpoint import Checkpoint
from .errors import C2spTlogVerificationError
from .signed_note import (
    SignedNoteKey,
    parse_signed_note_verifier_key,
    verified_cosignature_timestamp,
    verify_checkpoint_signature,
    verify_note_signature,
)

_DECIMAL_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")


@dataclass
class C2spTlogQuorumRule:
    """A quorum rule node: kind is 'none', 'witness', or 'threshold'."""

    kind: str
    key: SignedNoteKey | str | None = None
    threshold: int = 0
    members: list[C2spTlogQuorumRule] = field(default_factory=list)


@dataclass
class C2spTlogOriginPolicy:
    """Trust policy for one checkpoint origin."""

    log_keys: list[SignedNoteKey | str]
    witness_keys: list[SignedNoteKey | str] = field(default_factory=list)
    quorum: int | None = None
    quorum_rule: C2spTlogQuorumRule | None = None
    unchained: bool = False


@dataclass
class C2spTlogEpochPolicy:
    """One trust epoch of an epoch policy.

    ``policy`` is the epoch's complete single-log policy. ``min_tree_size`` and
    ``max_tree_size`` are inclusive checkpoint tree-size bounds; ``None`` leaves
    that side open. Build epoch policies with
    :func:`~dnsid.c2sp_tlog.create_c2sp_tlog_epoch_policy`, which validates them.
    """

    id: str
    policy: C2spTlogPolicy
    min_tree_size: int | None = None
    max_tree_size: int | None = None


@dataclass
class C2spTlogPolicy:
    """Local C2SP trust policy: per-origin log/witness keys and quorum.

    An epoch policy leaves ``origins`` empty and carries ``epochs`` instead. It
    accepts a checkpoint only when one epoch accepts it completely: that
    epoch's log signature, tree-size bounds and witness quorum. Signatures are
    never combined across epochs.
    """

    origins: dict[str, C2spTlogOriginPolicy]
    scope: str | None = None
    epochs: list[C2spTlogEpochPolicy] = field(default_factory=list)


@dataclass
class NormalizedOriginPolicy:
    """Resolved per-origin policy: parsed keys and defaulted quorum settings."""

    log_keys: list[SignedNoteKey]
    witness_keys: list[SignedNoteKey]
    quorum: int
    quorum_rule: C2spTlogQuorumRule
    unchained: bool


@dataclass
class CheckpointPolicyResult:
    """Outcome of checkpoint policy enforcement."""

    accepted_witness_timestamps: list[int]
    checkpoint_witness_time: datetime.datetime | None = None
    trust_epoch: str = ""


def normalized_origin_policy(policy: C2spTlogPolicy, origin: str) -> NormalizedOriginPolicy:
    """Resolve, validate, and normalize the policy for *origin*."""
    p = policy.origins.get(origin)
    if p is None:
        raise C2spTlogVerificationError(f"no local C2SP policy for origin {origin}")
    log_keys = [_as_key(k) for k in p.log_keys]
    witness_keys = [_as_key(k) for k in p.witness_keys]
    quorum = p.quorum if p.quorum is not None else 0
    if quorum < 0:
        raise C2spTlogVerificationError(
            "checkpoint witness quorum must be a non-negative integer"
        )
    if quorum > len(witness_keys):
        raise C2spTlogVerificationError(
            "checkpoint witness quorum exceeds configured witnesses"
        )
    if not log_keys:
        raise C2spTlogVerificationError("checkpoint policy requires at least one log key")
    if any(key.name != origin for key in log_keys):
        raise C2spTlogVerificationError("checkpoint log key name must match its origin")
    if any(
        key.signature_type is not None and key.signature_type != b"\x01"
        for key in log_keys
    ):
        raise C2spTlogVerificationError(
            "checkpoint log keys must use the supported log signature type 0x01"
        )
    if any(key.signature_type != b"\x04" for key in witness_keys):
        raise C2spTlogVerificationError(
            "checkpoint witness keys must use the supported cosignature type 0x04"
        )

    _assert_distinct_underlying_keys(log_keys, "checkpoint log keys")
    _assert_distinct_underlying_keys(witness_keys, "checkpoint witness keys")
    log_identities = {_key_identity(k) for k in log_keys}
    if any(_key_identity(k) in log_identities for k in witness_keys):
        raise C2spTlogVerificationError(
            "checkpoint log and witness keys must use distinct underlying public keys"
        )

    quorum_rule = _normalize_quorum_rule(
        p.quorum_rule if p.quorum_rule is not None else _flat_quorum_rule(witness_keys, quorum)
    )
    rule_witness_keys = _collect_witness_keys(quorum_rule)
    if any(key.signature_type != b"\x04" for key in rule_witness_keys):
        raise C2spTlogVerificationError(
            "checkpoint quorum witness keys must use the supported cosignature type 0x04"
        )
    _assert_distinct_underlying_keys(rule_witness_keys, "checkpoint quorum witness keys")
    if any(_key_identity(k) in log_identities for k in rule_witness_keys):
        raise C2spTlogVerificationError(
            "checkpoint log and witness keys must use distinct underlying public keys"
        )
    return NormalizedOriginPolicy(
        log_keys=log_keys,
        witness_keys=rule_witness_keys,
        quorum=_top_level_threshold(quorum_rule),
        quorum_rule=quorum_rule,
        unchained=p.unchained,
    )


def enforce_checkpoint_policy(
    checkpoint: Checkpoint,
    origin: str,
    policy: C2spTlogPolicy,
    scope: str,
    now_ms: float,
    max_clock_skew_ms: int = 0,
    *,
    max_checkpoint_age_ms: int | None = None,
) -> CheckpointPolicyResult:
    """Verify the checkpoint against the local trust policy for *origin*.

    Checks the log signature and evaluates the witness quorum; returns the
    accepted witness timestamps and the earliest one as the checkpoint's
    integration time. When *max_checkpoint_age_ms* is set, the accepted witness
    time must also be at most that old.

    For an epoch policy, epochs are tried in order. An epoch is relevant when
    the checkpoint carries a signature line under that epoch's log key name
    and key hash. A relevant epoch checks its log signature, its tree-size
    bounds, its own witness quorum and then freshness; the first epoch that
    passes every check is accepted and reported as ``trust_epoch``. Otherwise
    the error is the first relevant epoch's failure, or a missing log
    signature when no epoch is relevant.
    """
    if max_clock_skew_ms < 0:
        raise C2spTlogVerificationError("maximum clock skew must be a non-negative integer")
    if max_checkpoint_age_ms is not None and (
        type(max_checkpoint_age_ms) is not int or max_checkpoint_age_ms < 1
    ):
        raise C2spTlogVerificationError(
            "maximum checkpoint age must be a positive integer when supplied"
        )
    if policy.scope is not None and policy.scope != scope:
        raise C2spTlogVerificationError(
            f"C2SP policy scope {policy.scope} does not match {scope}"
        )
    if checkpoint.origin != origin:
        raise C2spTlogVerificationError(f"checkpoint origin mismatch: {checkpoint.origin}")
    if not policy.epochs:
        return _enforce_origin_policy(
            checkpoint, origin, policy, scope, now_ms, max_clock_skew_ms,
            max_checkpoint_age_ms, None,
        )
    if policy.origins:
        raise C2spTlogVerificationError(
            "C2SP epoch policy must carry its origins inside its epochs"
        )
    reported: C2spTlogVerificationError | None = None
    for epoch in policy.epochs:
        if not _epoch_log_key_present(checkpoint, origin, epoch):
            continue
        try:
            return _enforce_origin_policy(
                checkpoint, origin, epoch.policy, scope, now_ms, max_clock_skew_ms,
                max_checkpoint_age_ms, epoch,
            )
        except C2spTlogVerificationError as exc:
            if reported is None:
                reported = exc
    if reported is not None:
        raise reported
    raise C2spTlogVerificationError("checkpoint missing accepted log signature")


def policy_unchained(policy: C2spTlogPolicy, origin: str) -> bool:
    """Return whether *policy* verifies *origin*'s streams without chaining.

    An epoch policy is unchained only when every epoch is.
    """
    if policy.epochs:
        return all(
            normalized_origin_policy(epoch.policy, origin).unchained
            for epoch in policy.epochs
        )
    return normalized_origin_policy(policy, origin).unchained


def _epoch_log_key_present(
    checkpoint: Checkpoint, origin: str, epoch: C2spTlogEpochPolicy
) -> bool:
    """Report whether a signature line names this epoch's log key and key hash."""
    log_keys = normalized_origin_policy(epoch.policy, origin).log_keys
    return any(
        key.key_id is not None
        and sig.name == key.name
        and sig.key_hash == key.key_id
        for key in log_keys
        for sig in checkpoint.signatures
    )


def _assert_epoch_signature_lines(
    checkpoint: Checkpoint, origin_policy: C2spTlogOriginPolicy
) -> None:
    """Require the first line under every key of one epoch to verify.

    Within a trust epoch a signed note is opened as a whole, as C2SP
    signed-note verifiers do: the first signature line under each of the
    epoch's log and witness keys (by name and key hash) must verify, later
    duplicate lines are ignored, and lines under other keys are ignored.
    """
    known = [_as_key(k) for k in [*origin_policy.log_keys, *origin_policy.witness_keys]]
    for key in known:
        first = next(
            (
                sig
                for sig in checkpoint.signatures
                if sig.name == key.name
                and key.key_id is not None
                and sig.key_hash == key.key_id
            ),
            None,
        )
        if first is not None and not verify_note_signature(
            checkpoint.signed_text, first, key
        ):
            raise C2spTlogVerificationError(
                "checkpoint missing accepted log signature: the signature line "
                f"under trust epoch key {key.name} does not verify"
            )


def _enforce_origin_policy(
    checkpoint: Checkpoint,
    origin: str,
    policy: C2spTlogPolicy,
    scope: str,
    now_ms: float,
    max_clock_skew_ms: int,
    max_checkpoint_age_ms: int | None,
    epoch: C2spTlogEpochPolicy | None,
) -> CheckpointPolicyResult:
    if policy.epochs:
        raise C2spTlogVerificationError("C2SP trust epochs must not be nested")
    if policy.scope is not None and policy.scope != scope:
        raise C2spTlogVerificationError(
            f"C2SP policy scope {policy.scope} does not match {scope}"
        )
    p = normalized_origin_policy(policy, origin)
    if epoch is not None:
        _assert_epoch_signature_lines(checkpoint, policy.origins[origin])
    accepted_log_keys = (
        [k for k in p.log_keys if k.signature_type == b"\x01"]
        if scope == "public"
        else p.log_keys
    )
    if not any(verify_checkpoint_signature(checkpoint, k) for k in accepted_log_keys):
        raise C2spTlogVerificationError("checkpoint missing accepted log signature")
    if epoch is not None:
        if epoch.max_tree_size is not None and checkpoint.tree_size > epoch.max_tree_size:
            raise C2spTlogVerificationError(
                f"checkpoint size {checkpoint.tree_size} is above trust epoch "
                f"{epoch.id!r} max_tree_size {epoch.max_tree_size}"
            )
        if epoch.min_tree_size is not None and checkpoint.tree_size < epoch.min_tree_size:
            raise C2spTlogVerificationError(
                f"checkpoint size {checkpoint.tree_size} is below trust epoch "
                f"{epoch.id!r} min_tree_size {epoch.min_tree_size}"
            )
    if scope == "public" and p.quorum_rule.kind == "none":
        raise C2spTlogVerificationError(
            "public C2SP policy requires a non-zero witness quorum"
        )
    accepted = _evaluate_quorum(p.quorum_rule, checkpoint, now_ms, max_clock_skew_ms)
    if accepted is None:
        raise C2spTlogVerificationError(
            "checkpoint witness quorum not satisfied by valid timestamped cosignatures"
        )
    witness_time: datetime.datetime | None = None
    if accepted:
        witness_time = datetime.datetime.fromtimestamp(min(accepted), tz=datetime.UTC)
    if max_checkpoint_age_ms is not None:
        if witness_time is None:
            raise C2spTlogVerificationError(
                "checkpoint freshness requires an accepted timestamped witness quorum"
            )
        if now_ms - witness_time.timestamp() * 1000 > max_checkpoint_age_ms:
            raise C2spTlogVerificationError("checkpoint is stale")
    return CheckpointPolicyResult(
        accepted_witness_timestamps=accepted,
        checkpoint_witness_time=witness_time,
        trust_epoch=epoch.id if epoch is not None else "",
    )


def parse_c2sp_policy_file(text: str) -> C2spTlogPolicy:
    """Parse the C2SP text policy format (log/witness/group/quorum directives)."""
    _assert_policy_characters(text)
    logs: list[SignedNoteKey] = []
    witnesses: dict[str, SignedNoteKey] = {}
    rules: dict[str, C2spTlogQuorumRule] = {}
    quorum_rule: C2spTlogQuorumRule | None = None
    quorum_lines = 0

    for index, raw_line in enumerate(text.split("\n")):
        line = raw_line.strip("\t ")
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[\t ]+", line)
        directive = parts.pop(0)
        try:
            if directive == "log" and len(parts) in (1, 2):
                logs.append(parse_signed_note_verifier_key(parts[0]))
            elif directive == "witness" and len(parts) in (2, 3):
                name = parts[0]
                _assert_new_policy_name(name, witnesses, rules)
                key = parse_signed_note_verifier_key(parts[1])
                witnesses[name] = key
                rules[name] = C2spTlogQuorumRule(kind="witness", key=key)
            elif directive == "group" and len(parts) >= 3:
                name = parts.pop(0)
                _assert_new_policy_name(name, witnesses, rules)
                threshold_text = parts.pop(0)
                member_names = parts
                if len(set(member_names)) != len(member_names):
                    raise ValueError("group members must be distinct")
                members: list[C2spTlogQuorumRule] = []
                for member in member_names:
                    rule = rules.get(member)
                    if rule is None:
                        raise ValueError(
                            f"group references unknown preceding witness or group {member}"
                        )
                    members.append(rule)
                if threshold_text == "any":
                    threshold = 1
                elif threshold_text == "all":
                    threshold = len(members)
                else:
                    threshold = _parse_decimal_threshold(threshold_text)
                if threshold < 1 or threshold > len(members):
                    raise ValueError("invalid group threshold")
                rules[name] = C2spTlogQuorumRule(
                    kind="threshold", threshold=threshold, members=members
                )
            elif directive == "quorum" and len(parts) == 1:
                quorum_lines += 1
                if quorum_lines > 1:
                    raise ValueError("policy must contain exactly one quorum directive")
                if parts[0] == "none":
                    quorum_rule = C2spTlogQuorumRule(kind="none")
                else:
                    quorum_rule = rules.get(parts[0])
                    if quorum_rule is None:
                        raise ValueError(
                            f"quorum references unknown preceding witness or group {parts[0]}"
                        )
            else:
                raise ValueError("unsupported directive or wrong number of fields")
        except (ValueError, C2spTlogVerificationError) as cause:
            raise C2spTlogVerificationError(
                f"invalid C2SP policy line {index + 1}: {cause}"
            ) from cause
    if quorum_lines != 1 or quorum_rule is None:
        raise C2spTlogVerificationError("C2SP policy requires exactly one quorum directive")
    if any(
        key.signature_type is not None and key.signature_type != b"\x01" for key in logs
    ):
        raise C2spTlogVerificationError(
            "C2SP policy log keys must use the supported log signature type 0x01"
        )
    if any(key.signature_type != b"\x04" for key in witnesses.values()):
        raise C2spTlogVerificationError(
            "C2SP policy witness keys must use the supported cosignature type 0x04"
        )
    _assert_distinct_underlying_keys(logs, "C2SP policy logs")
    _assert_distinct_underlying_keys(list(witnesses.values()), "C2SP policy witnesses")
    log_identities = {_key_identity(k) for k in logs}
    if any(_key_identity(k) in log_identities for k in witnesses.values()):
        raise C2spTlogVerificationError(
            "C2SP policy log and witness keys must use distinct underlying public keys"
        )

    witness_keys: list[SignedNoteKey | str] = list(witnesses.values())
    quorum = _legacy_quorum(quorum_rule)
    origins: dict[str, C2spTlogOriginPolicy] = {}
    for log in logs:
        current = origins.get(log.name)
        if current is not None:
            current.log_keys.append(log)
        else:
            origins[log.name] = C2spTlogOriginPolicy(
                log_keys=[log],
                witness_keys=witness_keys,
                quorum=quorum,
                quorum_rule=quorum_rule,
            )
    return C2spTlogPolicy(origins=origins)


def _as_key(k: SignedNoteKey | str) -> SignedNoteKey:
    return parse_signed_note_verifier_key(k) if isinstance(k, str) else k


def _normalize_quorum_rule(rule: C2spTlogQuorumRule) -> C2spTlogQuorumRule:
    if rule.kind == "none":
        return rule
    if rule.kind == "witness":
        if rule.key is None:
            raise C2spTlogVerificationError("witness quorum rule requires a key")
        return C2spTlogQuorumRule(kind="witness", key=_as_key(rule.key))
    if rule.kind == "threshold":
        if rule.threshold < 1 or rule.threshold > len(rule.members):
            raise C2spTlogVerificationError("checkpoint quorum rule has an invalid threshold")
        return C2spTlogQuorumRule(
            kind="threshold",
            threshold=rule.threshold,
            members=[_normalize_quorum_rule(m) for m in rule.members],
        )
    raise C2spTlogVerificationError(f"unsupported quorum rule kind: {rule.kind}")


def _flat_quorum_rule(
    witness_keys: list[SignedNoteKey], quorum: int
) -> C2spTlogQuorumRule:
    if quorum == 0:
        return C2spTlogQuorumRule(kind="none")
    return C2spTlogQuorumRule(
        kind="threshold",
        threshold=quorum,
        members=[C2spTlogQuorumRule(kind="witness", key=k) for k in witness_keys],
    )


def _collect_witness_keys(rule: C2spTlogQuorumRule) -> list[SignedNoteKey]:
    if rule.kind == "none":
        return []
    if rule.kind == "witness":
        assert isinstance(rule.key, SignedNoteKey)  # normalized upstream
        return [rule.key]
    out: list[SignedNoteKey] = []
    for m in rule.members:
        out.extend(_collect_witness_keys(m))
    return out


def _evaluate_quorum(
    rule: C2spTlogQuorumRule,
    checkpoint: Checkpoint,
    now_ms: float,
    max_clock_skew_ms: int,
) -> list[int] | None:
    if rule.kind == "none":
        return []
    if rule.kind == "witness":
        assert isinstance(rule.key, SignedNoteKey)  # normalized upstream
        timestamp = verified_cosignature_timestamp(checkpoint, rule.key)
        if timestamp is not None and timestamp * 1000 <= now_ms + max_clock_skew_ms:
            return [timestamp]
        return None
    satisfied = [
        result
        for member in rule.members
        if (result := _evaluate_quorum(member, checkpoint, now_ms, max_clock_skew_ms))
        is not None
    ]
    if len(satisfied) < rule.threshold:
        return None
    satisfied.sort(key=lambda ts: min(ts) if ts else float("inf"), reverse=True)
    out: list[int] = []
    for member_result in satisfied[: rule.threshold]:
        out.extend(member_result)
    return out


def _assert_distinct_underlying_keys(keys: list[SignedNoteKey], label: str) -> None:
    identities = [_key_identity(k) for k in keys]
    if len(set(identities)) != len(identities):
        raise C2spTlogVerificationError(f"{label} must be distinct by underlying public key")


def _key_identity(key: SignedNoteKey) -> str:
    return f"{key.kind}\0{key.key_bytes.hex()}"


def _assert_policy_characters(text: str) -> None:
    for index, ch in enumerate(text):
        code = ord(ch)
        if code == 0x09 or code == 0x0A or code >= 0x20:
            continue
        raise C2spTlogVerificationError(f"invalid C2SP policy character at offset {index}")


def _assert_new_policy_name(
    name: str,
    witnesses: dict[str, SignedNoteKey],
    rules: dict[str, C2spTlogQuorumRule],
) -> None:
    if name == "none":
        raise ValueError("none is a reserved policy name")
    if name in witnesses or name in rules:
        raise ValueError(f"duplicate policy name {name}")


def _parse_decimal_threshold(value: str) -> int:
    if not _DECIMAL_RE.match(value):
        raise ValueError("invalid group threshold")
    return int(value)


def _legacy_quorum(rule: C2spTlogQuorumRule) -> int | None:
    if rule.kind == "none":
        return 0
    if rule.kind == "witness":
        return 1
    if all(member.kind == "witness" for member in rule.members):
        return rule.threshold
    return None


def _top_level_threshold(rule: C2spTlogQuorumRule) -> int:
    if rule.kind == "none":
        return 0
    if rule.kind == "witness":
        return 1
    return rule.threshold
