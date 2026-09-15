"""C2SP signed-note checkpoint parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .._utils import b64_std_decode
from .errors import C2spTlogParseError

_SIZE_RE = re.compile(r"^(0|[1-9][0-9]*)$")
# Signed-note signature line: "— <name> <base64>" (em dash) with "-- " fallback.
_SIG_RE = re.compile(r"^— (\S+)\s+([A-Za-z0-9+/=]+)$")
_SIG_RE_ASCII = re.compile(r"^-- (\S+)\s+([A-Za-z0-9+/=]+)$")


@dataclass
class NoteSignature:
    """One signature line from a signed note."""

    name: str
    signature: bytes
    key_hash: bytes | None = None
    raw: str = ""


@dataclass
class Checkpoint:
    """A parsed C2SP checkpoint (origin, tree size, root hash, signatures)."""

    origin: str
    tree_size: int
    root_hash: bytes
    signatures: list[NoteSignature] = field(default_factory=list)
    signed_text: str = ""


def parse_checkpoint(text: str) -> Checkpoint:
    """Parse a signed-note checkpoint into its body and signature lines."""
    normalized = text.replace("\r\n", "\n")
    sig_start = normalized.find("\n\n")
    if sig_start == -1:
        signed_text = normalized.rstrip() + "\n"
    else:
        signed_text = normalized[: sig_start + 1]
    body = signed_text.rstrip("\n").split("\n")
    if len(body) < 3:
        raise C2spTlogParseError("checkpoint must contain origin, size, and root hash")
    origin, size_text, root_text = body[0], body[1], body[2]
    if not origin:
        raise C2spTlogParseError("checkpoint missing origin")
    if not _SIZE_RE.match(size_text):
        raise C2spTlogParseError("checkpoint has invalid tree size")
    tree_size = int(size_text)
    try:
        root_hash = b64_std_decode(root_text)
    except Exception as exc:
        raise C2spTlogParseError(f"checkpoint root hash is not base64: {exc}") from exc
    if len(root_hash) != 32:
        raise C2spTlogParseError("checkpoint root hash must be SHA-256 sized")
    sig_text = "" if sig_start == -1 else normalized[sig_start + 2 :].strip()
    signatures = (
        [parse_note_signature(line) for line in sig_text.split("\n") if line]
        if sig_text
        else []
    )
    return Checkpoint(
        origin=origin,
        tree_size=tree_size,
        root_hash=root_hash,
        signatures=signatures,
        signed_text=signed_text,
    )


def parse_note_signature(line: str) -> NoteSignature:
    """Parse one "— name base64" signed-note signature line."""
    m = _SIG_RE.match(line) or _SIG_RE_ASCII.match(line)
    if not m:
        raise C2spTlogParseError("invalid signed-note signature line")
    try:
        raw_bytes = b64_std_decode(m.group(2))
    except Exception as exc:
        raise C2spTlogParseError(f"invalid signed-note signature base64: {exc}") from exc
    if len(raw_bytes) > 4:
        return NoteSignature(
            name=m.group(1),
            key_hash=raw_bytes[:4],
            signature=raw_bytes[4:],
            raw=line,
        )
    return NoteSignature(name=m.group(1), signature=raw_bytes, raw=line)
