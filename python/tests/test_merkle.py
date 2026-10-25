import hashlib
import random

import pytest

from veritaschain_vcp import merkle

# Certificate Transparency reference leaves and roots (RFC 6962 construction).
CT_LEAVES = [bytes.fromhex(x) for x in ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]]
CT_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


def leaves(n: int) -> list[bytes]:
    return [hashlib.sha256(str(i).encode()).digest() for i in range(n)]


def test_ct_roots():
    for n in range(1, 9):
        assert merkle.root(CT_LEAVES[:n]).hex() == CT_ROOTS[n - 1]


def test_empty_tree():
    assert merkle.root([]).hex() == hashlib.sha256(b"").hexdigest()


@pytest.mark.parametrize("n", range(1, 66))
def test_inclusion_all_indices(n):
    ls = leaves(n)
    tree = merkle.MerkleTree(ls)
    for i in range(n):
        p = tree.inclusion_proof(i)
        assert merkle.verify_inclusion(ls[i], i, n, p, tree.root)
        assert p == merkle.inclusion_proof(i, ls)


def test_inclusion_rejections():
    rng = random.Random(6962)
    for n in range(1, 40):
        ls = leaves(n)
        tree = merkle.MerkleTree(ls)
        for i in range(n):
            p = tree.inclusion_proof(i)
            r = tree.root
            assert not merkle.verify_inclusion(ls[i], n, n, p, r)
            assert not merkle.verify_inclusion(b"x" + ls[i], i, n, p, r)
            assert not merkle.verify_inclusion(ls[i], i, n, p + [r], r)
            if p:
                assert not merkle.verify_inclusion(ls[i], i, n, p[:-1], r)
                bad = list(p)
                j = rng.randrange(len(bad))
                bad[j] = bytes([bad[j][0] ^ 1]) + bad[j][1:]
                assert not merkle.verify_inclusion(ls[i], i, n, bad, r)
            if n > 1:
                other = (i + 1) % n
                assert not merkle.verify_inclusion(ls[i], other, n, p, r)


def test_size_is_not_authenticated_by_root_and_path():
    """A root and path alone do not fix the tree size (RFC 9162 signs size with root).

    VCP v1.2's root-only signature (section 6.3.1) leaves EventCount unauthenticated,
    so the verifier reports the size binding separately.
    """
    ls = leaves(3)
    tree = merkle.MerkleTree(ls)
    p = tree.inclusion_proof(0)
    assert merkle.verify_inclusion(ls[0], 0, 3, p, tree.root)
    assert merkle.verify_inclusion(ls[0], 0, 4, p, tree.root)


@pytest.mark.parametrize("n", range(1, 41))
def test_consistency_all_pairs(n):
    ls = leaves(n)
    big = merkle.MerkleTree(ls)
    for m in range(0, n + 1):
        small_root = merkle.root(ls[:m])
        p = big.consistency_proof(m)
        assert merkle.verify_consistency(m, n, small_root, big.root, p)
        if 0 < m < n:
            assert not merkle.verify_consistency(m, n, small_root, big.root, p[:-1])
            bad = list(p)
            bad[0] = bytes([bad[0][0] ^ 1]) + bad[0][1:]
            assert not merkle.verify_consistency(m, n, small_root, big.root, bad)
            assert not merkle.verify_consistency(m, n, big.root, big.root, p)
            wrong_old = merkle.root(leaves(m + 100)[100:])
            assert not merkle.verify_consistency(m, n, wrong_old, big.root, p)


def test_legacy_example_differs_where_expected():
    differ = [n for n in range(1, 17) if merkle.legacy_example_root(leaves(n)) != merkle.root(leaves(n))]
    assert differ == [3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15]
    # duplicate-node ambiguity in the example construction
    ls = leaves(3)
    assert merkle.legacy_example_root(ls) == merkle.legacy_example_root(ls + [ls[2]])
    assert merkle.root(ls) != merkle.root(ls + [ls[2]])
