"""Merkle Tree sui fingerprint F_j, con prove di inclusione in tempo/spazio O(log n).

Struttura e prove seguono l'implementazione vista nelle esercitazioni del corso:
foglia  H(F_j),  nodo interno  H(figlio_sx || figlio_dx),  duplicazione
dell'ultimo nodo se il livello e' dispari, prove con posizioni "left"/"right"
(sibling individuato con lo XOR dell'ultimo bit dell'indice).

Con la duplicazione dell'ultimo nodo uno stesso valore di radice puo' derivare da
liste di foglie di lunghezza diversa: questa ambiguita' e' chiusa a monte dal
protocollo, che firma il numero di foglie insieme alla radice e lo incrocia con il
numero di record presenti nella catena.
"""

from __future__ import annotations

from . import crypto


def _leaf(fingerprint: bytes) -> bytes:
    return crypto.sha256(fingerprint)


def _node(left: bytes, right: bytes) -> bytes:
    return crypto.sha256(left + right)


class MerkleTree:
    """Merkle Tree immutabile su una lista ordinata di fingerprint."""

    def __init__(self, fingerprints: list[bytes]) -> None:
        if not fingerprints:
            raise ValueError("il Merkle Tree richiede almeno una foglia")
        self.leaves = list(fingerprints)
        self.levels = self._build(self.leaves)

    @staticmethod
    def _build(fingerprints: list[bytes]) -> list[list[bytes]]:
        levels = [[_leaf(f) for f in fingerprints]]
        while len(levels[-1]) > 1:
            level = levels[-1]
            if len(level) % 2 == 1:
                level = level + [level[-1]]          # ultimo nodo duplicato se dispari
            levels.append([_node(level[i], level[i + 1]) for i in range(0, len(level), 2)])
        return levels

    @property
    def leaf_count(self) -> int:
        return len(self.leaves)

    def root(self) -> bytes:
        return self.levels[-1][0]

    def prove(self, index: int) -> list[tuple[str, bytes]]:
        """Prova di inclusione della foglia `index`: lista di (posizione, hash_fratello),
        lunghezza O(log n).  `posizione` = "left"/"right" indica dove sta il fratello."""
        if not (0 <= index < len(self.leaves)):
            raise IndexError("indice di foglia fuori intervallo")
        proof: list[tuple[str, bytes]] = []
        idx = index
        for level in self.levels[:-1]:
            if len(level) % 2 == 1:
                level = level + [level[-1]]
            sibling = idx ^ 1                        # fratello: nodo con l'ultimo bit invertito
            position = "right" if sibling > idx else "left"
            proof.append((position, level[sibling]))
            idx //= 2
        return proof


def verify_proof(fingerprint: bytes, proof: list[tuple[str, bytes]], root: bytes) -> bool:
    """Ricostruisce il cammino foglia -> radice e lo confronta con `root`."""
    acc = _leaf(fingerprint)
    for position, sibling in proof:
        if position == "right":                     # fratello a destra: il nostro nodo va a sinistra
            acc = _node(acc, sibling)
        elif position == "left":
            acc = _node(sibling, acc)
        else:
            return False
    return acc == root
