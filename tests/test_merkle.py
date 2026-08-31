"""Merkle Tree: prove di inclusione O(log n), lunghezza logaritmica; e
iniettivita' della serializzazione canonica (`wire`).
"""

from __future__ import annotations

import math

import pytest

from src import crypto
from src.crypto import unwire, wire
from src.merkle import MerkleTree, verify_proof


def _leaves(n: int) -> list[bytes]:
    return [crypto.sha256(i.to_bytes(4, "big")) for i in range(n)]


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31, 64, 100])
def test_proof_roundtrip_all_indices(n):
    leaves = _leaves(n)
    tree = MerkleTree(leaves)
    root = tree.root()
    for i in range(n):
        proof = tree.prove(i)
        assert verify_proof(leaves[i], proof, root) is True
        assert verify_proof(crypto.sha256(b"altro"), proof, root) is False


@pytest.mark.parametrize("n", [8, 64, 512, 4096, 30000])
def test_proof_length_is_logarithmic(n):
    tree = MerkleTree(_leaves(n))
    proof = tree.prove(n // 3)
    assert len(proof) == math.ceil(math.log2(n))


def test_tree_commits_to_leaf_count():
    base = _leaves(5)
    assert MerkleTree(base).leaf_count == 5
    assert MerkleTree(base).root() != MerkleTree(base + [crypto.sha256(b"x")]).root()


def test_empty_tree_rejected():
    with pytest.raises(ValueError):
        MerkleTree([])


# --------------------------------------------------------------- wire injective
def test_wire_roundtrip():
    fields = [b"\x00\x01", 42, "id-elezione", ["Lista A", "Lista B", "Lista C"], 0]
    assert unwire(wire(fields)) == fields


def test_wire_is_injective_on_variable_length_fields():
    """Tuple diverse di campi a lunghezza variabile non devono collidere nella
    serializzazione."""
    assert wire(["a", "bc"]) != wire(["ab", "c"])
    assert wire([["a", "b"], "c"]) != wire([["a"], "b", "c"])
    assert wire([b"", b"x"]) != wire([b"x", b""])
