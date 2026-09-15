"""RFC 6962-style Merkle tree hashing and inclusion proofs."""

from __future__ import annotations

import hashlib


def sha256(*chunks: bytes) -> bytes:
    """Return the SHA-256 digest of the concatenation of *chunks*."""
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


def leaf_hash(entry_bytes: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA-256(0x00 || entry)."""
    return sha256(b"\x00", entry_bytes)


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash: SHA-256(0x01 || left || right)."""
    return sha256(b"\x01", left, right)


def inclusion_root(leaf: bytes, index: int, tree_size: int, proof: list[bytes]) -> bytes:
    """Recompute the tree root from a leaf hash and its inclusion proof."""
    if index < 0 or tree_size <= index:
        raise ValueError("invalid inclusion index or tree size")
    hash_ = leaf
    i = index
    n = tree_size
    for sibling in proof:
        if i % 2 == 1:
            hash_ = node_hash(sibling, hash_)
        elif i < n - 1:
            hash_ = node_hash(hash_, sibling)
        else:
            hash_ = node_hash(sibling, hash_)
        i //= 2
        n = (n + 1) // 2
    return hash_


def verify_inclusion(
    entry_bytes: bytes, index: int, tree_size: int, root_hash: bytes, proof: list[bytes]
) -> bool:
    """True if *entry_bytes* is provably included at *index* under *root_hash*."""
    return inclusion_root(leaf_hash(entry_bytes), index, tree_size, proof) == root_hash


def verify_consistency(
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: list[bytes],
) -> bool:
    """Verify an RFC 6962 consistency proof between two checkpoints."""
    if old_size < 1 or old_size > new_size:
        return False
    if len(old_root) != 32 or len(new_root) != 32 or any(len(node) != 32 for node in proof):
        return False
    if old_size == new_size:
        return not proof and old_root == new_root

    old_index = old_size - 1
    new_index = new_size - 1
    while old_index & 1:
        old_index >>= 1
        new_index >>= 1

    offset = 0
    if old_size & (old_size - 1) == 0:
        old_hash = new_hash = old_root
    else:
        if not proof:
            return False
        old_hash = new_hash = proof[0]
        offset = 1

    for node in proof[offset:]:
        if new_index == 0:
            return False
        if old_index & 1 or old_index == new_index:
            old_hash = node_hash(node, old_hash)
            new_hash = node_hash(node, new_hash)
            while old_index and old_index & 1 == 0:
                old_index >>= 1
                new_index >>= 1
        else:
            new_hash = node_hash(new_hash, node)
        old_index >>= 1
        new_index >>= 1
    return new_index == 0 and old_hash == old_root and new_hash == new_root


def merkle_root_from_entries(entries: list[bytes]) -> bytes:
    """Compute the RFC 6962 root over a complete, ordered entry list."""
    if not entries:
        return sha256()
    level = [leaf_hash(e) for e in entries]
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0]
