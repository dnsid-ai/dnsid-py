"""Signed-note verifier keys and checkpoint signature verification.

Supports Ed25519 log signatures (signature type 0x01) and timestamped
Ed25519 cosignatures (cosignature/v1, signature type 0x04).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from .._utils import b64_std_decode
from .checkpoint import Checkpoint, NoteSignature
from .errors import C2spTlogParseError

_HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2})+$")
_MAX_COSIG_TIMESTAMP = 0x7FFF_FFFF_FFFF_FFFF


@dataclass
class SignedNoteKey:
    """A signed-note verifier key (name + Ed25519 public key bytes)."""

    name: str
    key_bytes: bytes
    kind: str = "ed25519"
    key_id: bytes | None = None
    signature_type: bytes | None = None


def parse_signed_note_verifier_key(text: str) -> SignedNoteKey:
    """Parse a signed-note verifier key from its text form.

    Accepts the C2SP ``name+hexid+base64`` form as well as the ``name base64``
    and ``name ed25519 base64`` forms.  The base64 key material is either a
    bare 32-byte Ed25519 key or a signature-type byte followed by the key.

    Raises:
        C2spTlogParseError: If the text matches none of the supported forms,
            the key ID is not four bytes, or the key material is invalid.
    """
    trimmed = text.strip()
    first_plus = trimmed.find("+")
    second_plus = trimmed.find("+", first_plus + 1) if first_plus != -1 else -1
    if first_plus > 0 and second_plus > first_plus + 1:
        name = trimmed[:first_plus]
        key_id = _from_hex(trimmed[first_plus + 1 : second_plus])
        if len(key_id) != 4:
            raise C2spTlogParseError("signed-note key ID must be four bytes")
        key_bytes, signature_type = _decode_key(trimmed[second_plus + 1 :])
        return SignedNoteKey(
            name=name, key_bytes=key_bytes, key_id=key_id, signature_type=signature_type
        )
    parts = trimmed.split()
    if len(parts) == 2:
        key_bytes, signature_type = _decode_key(parts[1])
        return SignedNoteKey(name=parts[0], key_bytes=key_bytes, signature_type=signature_type)
    if len(parts) == 3 and parts[1].lower() == "ed25519":
        key_bytes, signature_type = _decode_key(parts[2])
        return SignedNoteKey(name=parts[0], key_bytes=key_bytes, signature_type=signature_type)
    raise C2spTlogParseError("unsupported signed-note verifier key")


def verify_checkpoint_signature(checkpoint: Checkpoint, key: SignedNoteKey) -> bool:
    """True if any of the checkpoint's signature lines verifies under *key*."""
    return any(
        sig.name == key.name
        and _key_id_matches(sig, key)
        and verify_note_signature(checkpoint.signed_text, sig, key)
        for sig in checkpoint.signatures
    )


def verified_cosignature_timestamp(checkpoint: Checkpoint, key: SignedNoteKey) -> int | None:
    """Return the verified cosignature/v1 timestamp (epoch seconds) under *key*.

    Returns None if *key* is not a cosignature/v1 key (signature type 0x04) or
    the checkpoint carries no valid timestamped cosignature from it.
    """
    if key.signature_type is None or key.signature_type != b"\x04":
        return None
    for sig in checkpoint.signatures:
        if (
            sig.name != key.name
            or not _key_id_matches(sig, key)
            or not verify_note_signature(checkpoint.signed_text, sig, key)
            or len(sig.signature) != 72
        ):
            continue
        timestamp = int.from_bytes(sig.signature[:8], "big")
        if timestamp <= _MAX_COSIG_TIMESTAMP:
            return timestamp
    return None


def verify_note_signature(message: str, sig: NoteSignature, key: SignedNoteKey) -> bool:
    r"""Verify one signed-note signature line against *key*.

    Type 0x01 is a plain Ed25519 signature over the note body.  Type 0x04 is a
    cosignature/v1: an 8-byte big-endian timestamp followed by an Ed25519
    signature over "cosignature/v1\ntime <t>\n" + body.
    """
    if key.kind != "ed25519" or len(key.key_bytes) != 32:
        return False
    if key.signature_type is not None and len(key.signature_type) != 1:
        return False
    signature_type = key.signature_type[0] if key.signature_type else 0x01
    signed_message = message
    signature = sig.signature
    if signature_type == 0x01:
        if len(signature) != 64:
            return False
    elif signature_type == 0x04:
        if len(signature) != 72:
            return False
        timestamp = int.from_bytes(signature[:8], "big")
        if timestamp > _MAX_COSIG_TIMESTAMP:
            return False
        signed_message = f"cosignature/v1\ntime {timestamp}\n{message}"
        signature = signature[8:]
    else:
        return False
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(key.key_bytes)
        public_key.verify(signature, signed_message.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


def _key_id_matches(sig: NoteSignature, key: SignedNoteKey) -> bool:
    if key.key_id is None:
        return True
    if sig.key_hash is None:
        return False
    return sig.key_hash == key.key_id


def _decode_key(s: str) -> tuple[bytes, bytes | None]:
    try:
        b = b64_std_decode(s)
    except Exception as exc:
        raise C2spTlogParseError(f"invalid verifier key base64: {exc}") from exc
    if len(b) == 32:
        return b, None
    if len(b) == 33:
        return b[1:], b[:1]
    raise C2spTlogParseError(
        "Ed25519 verifier key must contain a signature type and 32-byte key"
    )


def _from_hex(s: str) -> bytes:
    if not _HEX_RE.match(s):
        raise C2spTlogParseError("invalid signed-note key ID")
    return bytes.fromhex(s)
