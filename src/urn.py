"""Urna pubblica ibrida: hash chain append-only + indice Merkle.

Struttura ibrida:
  - hash chain (hash pointer + firma AE su ogni blocco): sequenza storica, rende
    rilevabili le modifiche retroattive;
  - Merkle Tree sui fingerprint F_j: prove di inclusione in O(log n) per la
    verifica individuale.

L'urna NON contiene mai il ciphertext C_j: pubblica solo K_j = H(C_j) e
F_j = H(K_j || eta_j).

Pubblicazione per finestre: i record accettati sono bufferizzati e pubblicati a
blocchi; l'indice j e' fissato all'accettazione (dall'AE) e non cambia.  Al
termine di ogni finestra si pubblica una Merkle Root (firmata dall'AE, co-firmata
dal SA); alla chiusura la Root definitiva dentro il Record_chiusura.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from . import crypto
from .merkle import MerkleTree, verify_proof
from .messages import (
    ClosureRecord,
    CoSignedRoot,
    ElectionParams,
    FinalDocument,
    GenesisRecord,
    InvalidRecord,
    VoteRecord,
)

ChainBlock = GenesisRecord | VoteRecord | InvalidRecord | ClosureRecord


@dataclass
class _Pending:
    j: int
    k_j: bytes
    f_j: bytes


class PublicUrn:
    """Registro pubblico dell'AE.  Espone una vista di sola lettura via `view()`."""

    def __init__(self, params: ElectionParams, pu_ele: RSAPublicKey,
                 ae_private_key: RSAPrivateKey, ae_public_key: RSAPublicKey) -> None:
        self.params = params
        self._ae_priv = ae_private_key
        self._ae_pub = ae_public_key
        # Blocco genesi Record_0 = Params firmato dall'AE.
        self.chain: list[ChainBlock] = [GenesisRecord.create(params, pu_ele, ae_private_key)]
        self._pending: list[_Pending] = []
        self.roots: list[CoSignedRoot] = []
        self.final_document: FinalDocument | None = None
        self.closed = False
        self._window_counter = 0

    # ------------------------------------------ ricezione e pubblicazione per finestre
    def buffer_record(self, j: int, k_j: bytes, f_j: bytes) -> None:
        """L'AE registra internamente un voto accettato; la pubblicazione del
        Record_j e' differita alla prossima finestra.  j e' gia' fissato dall'AE."""
        if self.closed:
            raise RuntimeError("urna chiusa: nessun nuovo record")
        self._pending.append(_Pending(j, k_j, f_j))

    def pending_count(self) -> int:
        return len(self._pending)

    def _materialize_pending(self) -> int:
        n = len(self._pending)
        for pr in sorted(self._pending, key=lambda p: p.j):
            prev = self.chain[-1].block_digest()
            self.chain.append(VoteRecord.create(pr.j, pr.k_j, pr.f_j, prev, self._ae_priv))
        self._pending.clear()
        return n

    def flush_window(self) -> CoSignedRoot | None:
        """Accoda i Record_j bufferizzati alla hash chain, poi pubblica la nuova
        Merkle Root intermedia (firmata dall'AE; il SA la co-firmera' leggendola
        dalla vista pubblica)."""
        if self.closed:
            raise RuntimeError("urna chiusa")
        if self._materialize_pending() == 0:
            return None
        return self._publish_root()

    def _fingerprints(self) -> list[bytes]:
        return [b.f_j for b in self.chain if isinstance(b, VoteRecord)]

    def _publish_root(self) -> CoSignedRoot:
        leaves = self._fingerprints()
        root_bytes = MerkleTree(leaves).root() if leaves else crypto.sha256(b"")
        # Idempotenza: non ripubblicare una Root identica (evita doppioni quando la
        # chiusura segue una finestra che non ha aggiunto record).
        if self.roots and self.roots[-1].root == root_bytes and self.roots[-1].leaf_count == len(leaves):
            return self.roots[-1]
        root = CoSignedRoot.create_ae(self._window_counter, root_bytes, len(leaves), self._ae_priv)
        self.roots.append(root)
        self._window_counter += 1
        return root

    def attach_cosigned_roots(self, cosigned: list[CoSignedRoot]) -> None:
        """Sostituisce le Root pubblicate con le versioni co-firmate dal SA
        (prodotte dal SA leggendo la vista pubblica dell'urna)."""
        by_marker = {(r.window_index, r.root): r for r in cosigned}
        for i, r in enumerate(self.roots):
            repl = by_marker.get((r.window_index, r.root))
            if repl is not None:
                self.roots[i] = repl

    # ----------------------------------------------------------- chiusura dell'urna
    def close(self) -> ClosureRecord:
        """Accoda i record residui, pubblica la Merkle Root DEFINITIVA, poi il
        Record_chiusura con k_totale e MerkleRoot_finale."""
        if self.closed:
            raise RuntimeError("urna gia' chiusa")
        self._materialize_pending()
        leaves = self._fingerprints()
        if leaves:
            final_root = self._publish_root().root  # Root definitiva co-firmabile dal SA
        else:
            final_root = crypto.sha256(b"")
        prev = self.chain[-1].block_digest()
        closure = ClosureRecord.create(len(leaves), final_root, prev, self._ae_priv)
        self.chain.append(closure)
        self.closed = True
        return closure

    # ------------------------------------------------ record di invalidazione (scrutinio)
    def append_invalid(self, j: int, k_j: bytes, motivo: str) -> InvalidRecord:
        """Accoda alla catena un Invalid_j firmato (scheda fuori range/malformata)."""
        if not self.closed:
            raise RuntimeError("gli Invalid_j si accodano solo dopo la chiusura")
        prev = self.chain[-1].block_digest()
        rec = InvalidRecord.create(self.params.id_elezione, j, k_j, motivo, prev, self._ae_priv)
        self.chain.append(rec)
        return rec

    def publish_final_document(self, doc: FinalDocument) -> None:
        self.final_document = doc

    # ================================================================ query
    def closure_record(self) -> ClosureRecord:
        for b in self.chain:
            if isinstance(b, ClosureRecord):
                return b
        raise RuntimeError("urna non ancora chiusa")

    def final_root_bytes(self) -> bytes:
        return self.closure_record().merkle_root_finale

    def final_cosigned_root(self) -> CoSignedRoot:
        """La Root definitiva co-firmata (l'ultima che coincide con
        MerkleRoot_finale nel Record_chiusura)."""
        target = self.final_root_bytes()
        for r in reversed(self.roots):
            if r.root == target:
                return r
        raise RuntimeError("Root definitiva co-firmata non trovata")

    def merkle_proof_for(self, f_j: bytes) -> tuple[list[tuple[str, bytes]], bytes]:
        """Prova di inclusione per la verifica individuale: (proof, root definitiva)."""
        leaves = self._fingerprints()
        try:
            idx = leaves.index(f_j)
        except ValueError as exc:
            raise KeyError("fingerprint non presente tra i record accettati") from exc
        tree = MerkleTree(leaves)
        return tree.prove(idx), tree.root()

    def view(self) -> "UrnView":
        return UrnView(self)


class UrnView:
    """Vista di sola lettura: cio' che SA, Verificatore Pubblico ed elettori
    osservano.  Nessun accesso all'archivio privato dell'AE."""

    def __init__(self, urn: PublicUrn) -> None:
        self._urn = urn

    def chain(self) -> list[ChainBlock]:
        return list(self._urn.chain)

    def genesis(self) -> GenesisRecord:
        return self._urn.chain[0]

    def published_roots(self) -> list[CoSignedRoot]:
        return list(self._urn.roots)

    def final_cosigned_root(self) -> CoSignedRoot:
        return self._urn.final_cosigned_root()

    def final_document(self) -> FinalDocument | None:
        return self._urn.final_document

    def ae_public_key(self) -> RSAPublicKey:
        return self._urn._ae_pub

    def params(self) -> ElectionParams:
        return self._urn.params

    def merkle_proof_for(self, f_j: bytes):
        return self._urn.merkle_proof_for(f_j)

    def verify_membership(self, f_j: bytes, proof, root: bytes) -> bool:
        return verify_proof(f_j, proof, root)
