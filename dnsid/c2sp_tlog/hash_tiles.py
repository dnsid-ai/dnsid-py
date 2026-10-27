"""Authenticate checkpoint continuity using only candidate-tree hash tiles."""

from __future__ import annotations

from collections.abc import Generator

from .._verification_budget import remaining_seconds
from .checkpoint_store import TrustedCheckpoint
from .errors import (
    C2spCheckpointConsistencyError,
    C2spLifecycleErrorCategory,
    C2spTlogTransportError,
)
from .merkle import node_hash
from .tiles import tile_path


def _hash_root(hashes: list[bytes], tail: bytes | None = None) -> bytes:
    # A lower-level right edge is smaller than each hash here, not another leaf.
    if not hashes:
        assert tail is not None
        return tail
    if len(hashes) == 1 and tail is None:
        return hashes[0]
    split = 1 << (len(hashes).bit_length() - 1)
    if split == len(hashes) and tail is None:
        split //= 2
    return node_hash(_hash_root(hashes[:split]), _hash_root(hashes[split:], tail))


def consistency_tiles(
    prefix: str,
    trusted: TrustedCheckpoint,
    candidate: TrustedCheckpoint,
    max_tree_size: int,
) -> Generator[tuple[str, int], bytes, None]:
    """Verify both roots, authenticating every tile before comparing trusted history."""
    tiles: dict[tuple[int, int], list[bytes]] = {}
    authenticated: set[tuple[int, int]] = set()
    n = candidate.tree_size

    def invalid(message: str) -> C2spCheckpointConsistencyError:
        return C2spCheckpointConsistencyError(
            message, category=C2spLifecycleErrorCategory.INVALID_EVIDENCE,
            trusted=trusted, observed=candidate,
        )

    if not 0 < trusted.tree_size < n <= max_tree_size:
        raise invalid("hash-tile checkpoint sizes exceed configured limits")

    def read(level: int, index: int) -> Generator[tuple[str, int], bytes, list[bytes]]:
        key = level, index
        if key not in tiles:
            remaining_seconds()
            width = min(256, (n >> (8 * level)) - index * 256)
            assert 1 <= width <= 256
            partial = width if width < 256 else None
            try:
                data = yield tile_path(prefix, level, index, partial), 32 * width
            except C2spTlogTransportError as exc:
                if partial is None or exc.status_code not in (403, 404):
                    raise
                remaining_seconds()
                data = yield tile_path(prefix, level, index), 8192
                if len(data) != 8192:
                    raise invalid("full hash tile has an invalid length")
                data = data[:32 * width]
            remaining_seconds()
            if len(data) != 32 * width:
                raise invalid("hash tile has an invalid length")
            tiles[key] = [data[i:i + 32] for i in range(0, len(data), 32)]
        return tiles[key]

    def root(size: int, *, edge: bool = False) -> Generator[tuple[str, int], bytes, bytes]:
        tail = None
        level = 0
        while size:
            width = size % 256
            if width:
                key = level, size // 256
                hashes = yield from read(*key)
                tail = _hash_root(hashes[:width], tail)
                if edge:
                    authenticated.add(key)
            size //= 256
            level += 1
        assert tail is not None
        return tail

    if (yield from root(n, edge=True)) != candidate.root_hash:
        raise invalid("hash tiles do not reproduce the candidate checkpoint root")
    old_root = yield from root(trusted.tree_size)

    def authenticate(key: tuple[int, int]) -> Generator[tuple[str, int], bytes, None]:
        if key in authenticated:
            return
        level, index = key
        own = tiles[key]
        assert len(own) == 256
        parent_key = level + 1, index // 256
        parent = yield from read(*parent_key)
        yield from authenticate(parent_key)
        # Hash this tile's entries, not the parent entry that claims its root.
        if _hash_root(own) != parent[index % 256]:
            raise invalid("hash tile does not authenticate against the candidate checkpoint")
        authenticated.add(key)

    for key in list(tiles):
        yield from authenticate(key)
    remaining_seconds()
    if old_root != trusted.root_hash:
        raise C2spCheckpointConsistencyError(
            "candidate-authenticated hash tiles contradict the trusted checkpoint root",
            category=C2spLifecycleErrorCategory.LOG_INCONSISTENT,
            trusted=trusted, observed=candidate,
        )
