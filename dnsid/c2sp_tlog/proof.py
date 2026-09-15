"""c2sp.org/tlog-proof@v1 parsing and verification."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .._utils import b64_std_decode
from .checkpoint import Checkpoint, parse_checkpoint
from .errors import C2spTlogParseError, C2spTlogVerificationError
from .merkle import verify_inclusion
from .policy import C2spTlogPolicy, enforce_checkpoint_policy

_B64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_INT_RE = re.compile(r"^(0|[1-9][0-9]*)$")


@dataclass
class TlogProofV1:
    """A parsed c2sp.org/tlog-proof@v1 document."""

    index: int
    hashes: list[bytes]
    checkpoint: Checkpoint
    extra: list[str] = field(default_factory=list)


def parse_tlog_proof_v1(text: str) -> TlogProofV1:
    """Parse the tlog-proof@v1 text format (header + inclusion hashes + checkpoint)."""
    if "\r" in text:
        raise C2spTlogParseError("tlog proof must use LF line endings")
    split = text.find("\n\n")
    if split == -1:
        raise C2spTlogParseError("tlog-proof@v1 missing checkpoint separator")
    header = text[:split].split("\n")
    if header[0] != "c2sp.org/tlog-proof@v1":
        raise C2spTlogParseError("missing c2sp.org/tlog-proof@v1 magic")
    hashes: list[bytes] = []
    extra: list[str] = []
    cursor = 1
    if cursor < len(header) and header[cursor].startswith("extra "):
        encoded = header[cursor][6:]
        if not _B64_RE.match(encoded):
            raise C2spTlogParseError("invalid proof extra data")
        extra.append(encoded)
        cursor += 1
    if cursor >= len(header) or not header[cursor].startswith("index "):
        raise C2spTlogParseError("tlog proof missing index")
    index = _parse_safe_int(header[cursor][6:], "proof index")
    cursor += 1
    for line in header[cursor:]:
        if not _B64_RE.match(line):
            raise C2spTlogParseError("invalid inclusion proof hash")
        hash_ = b64_std_decode(line)
        if len(hash_) != 32:
            raise C2spTlogParseError("inclusion proof hash must be SHA-256 sized")
        hashes.append(hash_)
    return TlogProofV1(
        index=index,
        hashes=hashes,
        extra=extra,
        checkpoint=parse_checkpoint(text[split + 2 :]),
    )


def verify_c2sp_tlog_proof(
    entry_bytes: bytes,
    proof: TlogProofV1 | str,
    policy: C2spTlogPolicy,
    origin: str | None = None,
    scope: str = "testnet",
    now_ms: float = 0,
    max_clock_skew_ms: int = 0,
) -> TlogProofV1:
    """Verify an inclusion proof against a policy-authenticated checkpoint."""
    p = parse_tlog_proof_v1(proof) if isinstance(proof, str) else proof
    enforce_checkpoint_policy(
        p.checkpoint,
        origin if origin is not None else p.checkpoint.origin,
        policy,
        scope,
        now_ms,
        max_clock_skew_ms,
    )
    if not verify_inclusion(
        entry_bytes, p.index, p.checkpoint.tree_size, p.checkpoint.root_hash, p.hashes
    ):
        raise C2spTlogVerificationError("invalid C2SP inclusion proof")
    return p


def _parse_safe_int(s: str, name: str) -> int:
    if not _INT_RE.match(s):
        raise C2spTlogParseError(f"invalid {name}")
    return int(s)
