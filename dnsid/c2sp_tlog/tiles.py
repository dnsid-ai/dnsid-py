"""C2SP tile/entry-bundle paths and the length-prefixed bundle codec."""

from __future__ import annotations

from .errors import C2spTlogParseError


def checkpoint_path(prefix: str) -> str:
    """Return the fetch path of the log's checkpoint under *prefix*."""
    return f"{prefix}/checkpoint"


def tile_path(prefix: str, level: int, n: int, width: int | None = None) -> str:
    """Return the C2SP tlog-tiles fetch path for hash tile *n* at *level*.

    A partial tile (one not yet full) is addressed by passing its *width*,
    which appends the ``.p/<width>`` suffix defined by the tlog-tiles spec.
    """
    suffix = "" if width is None else f".p/{width}"
    return f"{prefix}/tile/{level}/{_tile_n(n)}{suffix}"


def entry_bundle_path(prefix: str, n: int, width: int | None = None) -> str:
    """Return the C2SP tlog-tiles fetch path for entry bundle *n*.

    A partial bundle is addressed by passing its *width*, which appends the
    ``.p/<width>`` suffix defined by the tlog-tiles spec.
    """
    suffix = "" if width is None else f".p/{width}"
    return f"{prefix}/tile/entries/{_tile_n(n)}{suffix}"


def _tile_n(n: int) -> str:
    """Encode a tile number in the C2SP x-grouped decimal path form.

    e.g. 0 → "000", 1234 → "x001/234", 1234067 → "x001/x234/067".
    """
    if n < 0:
        raise C2spTlogParseError("invalid C2SP tile number")
    digits = str(n)
    padded = digits.zfill(((len(digits) + 2) // 3) * 3)
    groups = [padded[i : i + 3] for i in range(0, len(padded), 3)]
    return "/".join(
        (g if i == len(groups) - 1 else f"x{g}") for i, g in enumerate(groups)
    )


def parse_entry_bundle(data: bytes) -> list[bytes]:
    """Decode a bundle of big-endian uint16-length-prefixed entries.

    Returns:
        The entry byte strings in bundle order.

    Raises:
        C2spTlogParseError: If a length prefix or entry is truncated.
    """
    out: list[bytes] = []
    off = 0
    while off < len(data):
        if off + 2 > len(data):
            raise C2spTlogParseError("truncated entry bundle length")
        length = (data[off] << 8) | data[off + 1]
        off += 2
        if off + length > len(data):
            raise C2spTlogParseError("truncated entry bundle entry")
        out.append(data[off : off + length])
        off += length
    return out


def encode_entry_bundle(entries: list[bytes]) -> bytes:
    """Encode entries into the big-endian uint16-length-prefixed bundle form.

    Raises:
        C2spTlogParseError: If any entry exceeds 65535 bytes.
    """
    out = bytearray()
    for e in entries:
        if len(e) > 0xFFFF:
            raise C2spTlogParseError("entry too large for bundle")
        out += len(e).to_bytes(2, "big")
        out += e
    return bytes(out)
