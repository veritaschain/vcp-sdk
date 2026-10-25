"""Merkle trees as RFC 6962 section 2.1 / RFC 9162 section 2.1 define them.

VCP v1.2 section 6.2.1 requires RFC 6962 construction, but its example code
duplicates the last node of an odd level, which RFC 6962 does not do. This SDK
follows the RFCs (INTERPRETATIONS.md, I-1). Roots for trees whose size is not a
power of two can therefore differ from roots made with the section 6.2.1
example code; :func:`legacy_example_root` reproduces that code so the
difference can be shown, and is not used by the verifier.

Leaves are the decoded 32-byte EventHash values (section 6.2.1:
``bytes.fromhex(h)``)::

    leaf hash  = SHA-256(0x00 || event_hash_bytes)
    node hash  = SHA-256(0x01 || left || right)
    empty tree = SHA-256("")
"""

from __future__ import annotations

import hashlib
from typing import Sequence

__all__ = [
    "MerkleTree",
    "leaf_hash",
    "node_hash",
    "root",
    "inclusion_proof",
    "verify_inclusion",
    "consistency_proof",
    "verify_consistency",
    "legacy_example_root",
]


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


class _Tree:
    """Subtree hashes over ``leaves[lo:hi]``, cached by range."""

    def __init__(self, leaves: Sequence[bytes]) -> None:
        self.leaves = list(leaves)
        self.cache: dict[tuple[int, int], bytes] = {}

    def mth(self, lo: int, hi: int) -> bytes:
        key = (lo, hi)
        hit = self.cache.get(key)
        if hit is not None:
            return hit
        n = hi - lo
        if n == 0:
            h = hashlib.sha256(b"").digest()
        elif n == 1:
            h = leaf_hash(self.leaves[lo])
        else:
            k = _split(n)
            h = node_hash(self.mth(lo, lo + k), self.mth(lo + k, hi))
        self.cache[key] = h
        return h

    def path(self, m: int, lo: int, hi: int) -> list[bytes]:
        n = hi - lo
        if n <= 1:
            return []
        k = _split(n)
        if m < k:
            return self.path(m, lo, lo + k) + [self.mth(lo + k, hi)]
        return self.path(m - k, lo + k, hi) + [self.mth(lo, lo + k)]

    def subproof(self, m: int, lo: int, hi: int, b: bool) -> list[bytes]:
        n = hi - lo
        if m == n:
            return [] if b else [self.mth(lo, hi)]
        k = _split(n)
        if m <= k:
            return self.subproof(m, lo, lo + k, b) + [self.mth(lo + k, hi)]
        return self.subproof(m - k, lo + k, hi, False) + [self.mth(lo, lo + k)]


class MerkleTree:
    """An RFC 6962 tree over a fixed list of leaf data, with cached subtree hashes."""

    def __init__(self, leaves: Sequence[bytes]) -> None:
        self._t = _Tree(leaves)
        self.size = len(self._t.leaves)
        self.root = self._t.mth(0, self.size)

    def inclusion_proof(self, index: int) -> list[bytes]:
        if not 0 <= index < self.size:
            raise IndexError("leaf index out of range")
        return self._t.path(index, 0, self.size)

    def consistency_proof(self, first: int) -> list[bytes]:
        if not 0 <= first <= self.size:
            raise IndexError("first size out of range")
        if first == 0 or first == self.size:
            return []
        return self._t.subproof(first, 0, self.size, True)


def root(leaves: Sequence[bytes]) -> bytes:
    """Merkle Tree Hash of the leaf data (RFC 9162 section 2.1.1)."""
    return MerkleTree(leaves).root


def inclusion_proof(index: int, leaves: Sequence[bytes]) -> list[bytes]:
    """Audit path for leaf ``index`` (RFC 9162 section 2.1.3.1), ordered leaf to root."""
    return MerkleTree(leaves).inclusion_proof(index)


def verify_inclusion(
    leaf: bytes, index: int, tree_size: int, proof: Sequence[bytes], expected_root: bytes
) -> bool:
    """Verify an inclusion proof (RFC 9162 section 2.1.3.2).

    ``leaf`` is the leaf *data* (the decoded EventHash), not its leaf hash.
    """
    if not all(isinstance(v, int) and not isinstance(v, bool) for v in (index, tree_size)):
        return False
    if index < 0 or index >= tree_size:
        return False
    fn, sn = index, tree_size - 1
    r = leaf_hash(leaf)
    for p in proof:
        if len(p) != 32:
            return False
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == expected_root


def consistency_proof(first: int, leaves: Sequence[bytes]) -> list[bytes]:
    """Consistency proof from size ``first`` to ``len(leaves)`` (RFC 9162 section 2.1.4.1)."""
    return MerkleTree(leaves).consistency_proof(first)


def verify_consistency(
    first: int, second: int, first_root: bytes, second_root: bytes, proof: Sequence[bytes]
) -> bool:
    """Verify a consistency proof (RFC 9162 section 2.1.4.2).

    As in RFC 9162 and transparency-dev/merkle, every tree is consistent with the
    empty tree: ``first == 0`` with an empty proof returns True for any roots.
    """
    if not all(isinstance(v, int) and not isinstance(v, bool) for v in (first, second)):
        return False
    if first < 0 or second < 0 or first > second:
        return False
    if first == second:
        return len(proof) == 0 and first_root == second_root
    if first == 0:
        # Every tree extends the empty tree; nothing to prove.
        return len(proof) == 0
    if len(proof) == 0 or any(len(c) != 32 for c in proof):
        return False
    path = list(proof)
    if first & (first - 1) == 0:  # exact power of two
        path = [first_root] + path
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0


def legacy_example_root(leaves: Sequence[bytes]) -> bytes:
    """Root produced by the VCP v1.2 section 6.2.1 example code (odd node duplicated).

    Provided only to show where it differs from RFC 6962. Not RFC 6962.
    """
    if not leaves:
        raise ValueError("the section 6.2.1 example code has no empty-tree root")
    level = [leaf_hash(x) for x in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(node_hash(level[i], right))
        level = nxt
    return level[0]
