"""Verificatore Pubblico - verifica universale.

Attore indipendente e passivo che opera solo sui dati pubblicati.  Controlla:

  - integrita' sequenziale della hash chain (tutti gli hash pointer a cascata);
  - validita' di TUTTE le firme dell'AE sui blocchi;
  - validita' delle DUE firme (AE e SA) su ogni Merkle Root pubblicata;
  - consistenza della Merkle Root ricalcolata con Record_chiusura e con Doc_finale;
  - coerenza numerica k_conformi + k_invalide = k_totale, con conteggio PER TIPO
    dei record effettivi;
  - corrispondenza dei record Invalid_j con i Record_j effettivi;
  - autenticita' del Doc_finale.

Limite strutturale: il Verificatore NON puo' accertare che l'AE abbia decifrato e
conteggiato onestamente ogni C_j; verifica tutto cio' che e' pubblicamente
verificabile.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from . import crypto
from .merkle import MerkleTree
from .messages import (
    MOTIVI_VALIDI,
    ClosureRecord,
    ElectionParams,
    GenesisRecord,
    InvalidRecord,
    VoteRecord,
)


@dataclass
class VerificationReport:
    checks: dict[str, bool] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def record(self, name: str, ok: bool, note: str | None = None) -> bool:
        self.checks[name] = ok
        if note and not ok:
            self.notes.append(f"{name}: {note}")
        return ok

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(self.checks.values())

    def render(self) -> str:
        lines = ["Verifica universale:"]
        for name, ok in self.checks.items():
            lines.append(f"  [{'OK ' if ok else 'FAIL'}] {name}")
        for n in self.notes:
            lines.append(f"    - {n}")
        lines.append(f"  => esito complessivo: {'POSITIVO' if self.ok else 'NEGATIVO'}")
        return "\n".join(lines)


class PublicVerifier:
    def __init__(self, params: ElectionParams, pu_sa: RSAPublicKey) -> None:
        self._params = params
        self._pu_sa = pu_sa

    def verify_universal(self, urn_view) -> VerificationReport:
        r = VerificationReport()
        pu_ae = urn_view.ae_public_key()
        chain = urn_view.chain()

        # ---- struttura di base ------------------------------------------------
        if not r.record("catena_non_vuota", len(chain) >= 3, "servono genesi + >=1 voto + chiusura"):
            return r
        genesis = chain[0]
        r.record("blocco_0_e_genesi", isinstance(genesis, GenesisRecord))

        closures = [b for b in chain if isinstance(b, ClosureRecord)]
        if not r.record("un_solo_record_chiusura", len(closures) == 1):
            return r
        closure = closures[0]

        # ---- autenticita' del blocco genesi e coerenza con i Params attesi ---
        r.record("firma_genesi", isinstance(genesis, GenesisRecord) and genesis.verify(pu_ae))
        if isinstance(genesis, GenesisRecord):
            r.record("params_genesi_coerenti", (
                genesis.id_elezione == self._params.id_elezione
                and genesis.n_opzioni == self._params.n_opzioni
                and genesis.lista_candidati == self._params.lista_candidati
                and abs(genesis.t_apertura - self._params.t_apertura) < 1e-3
                and abs(genesis.t_chiusura - self._params.t_chiusura) < 1e-3
            ))

        # ---- integrita' sequenziale della hash chain ------------------------
        seq_ok = True
        for k in range(1, len(chain)):
            if chain[k].prev_hash != chain[k - 1].block_digest():
                seq_ok = False
                r.notes.append(f"hash pointer rotto al blocco {k}")
                break
        r.record("integrita_sequenziale_hash_chain", seq_ok)

        # ---- firme dell'AE su OGNI blocco ---------------------------------
        r.record("firme_AE_su_ogni_blocco", all(b.verify(pu_ae) for b in chain))

        # ---- Merkle Root ricalcolata -------------------------------------
        fingerprints = [b.f_j for b in chain if isinstance(b, VoteRecord)]
        recomputed_root = MerkleTree(fingerprints).root() if fingerprints else crypto.sha256(b"")
        r.record("merkle_root_vs_record_chiusura", recomputed_root == closure.merkle_root_finale)

        # ---- co-firme AE + SA su TUTTE le Root pubblicate ----------------
        roots = urn_view.published_roots()
        roots_ok = len(roots) >= 1
        prev_count = -1
        for root in roots:
            if not root.verify_ae(pu_ae) or not root.verify_sa(self._pu_sa):
                roots_ok = False
                r.notes.append(f"Root finestra {root.window_index}: co-firma AE/SA non valida")
                break
            if root.leaf_count < prev_count:
                roots_ok = False
                r.notes.append("leaf_count delle Root non monotono")
                break
            prev_count = root.leaf_count
        r.record("cofirme_AE_SA_su_ogni_merkle_root", roots_ok)

        try:
            final_root = urn_view.final_cosigned_root()
            r.record("root_definitiva_cofirmata_coincide",
                     final_root.root == closure.merkle_root_finale
                     and final_root.verify_ae(pu_ae) and final_root.verify_sa(self._pu_sa))
        except RuntimeError as exc:
            r.record("root_definitiva_cofirmata_coincide", False, str(exc))

        # ---- Doc_finale -------------------------------------------------
        doc = urn_view.final_document()
        if not r.record("doc_finale_presente", doc is not None):
            return r
        r.record("firma_doc_finale", doc.verify(pu_ae))
        r.record("merkle_root_vs_doc_finale", doc.merkle_root_finale == recomputed_root)

        # ---- coerenza numerica (conteggio PER TIPO) -------------------
        k_totale_chain = sum(1 for b in chain if isinstance(b, VoteRecord))
        k_invalide_chain = sum(1 for b in chain if isinstance(b, InvalidRecord))
        k_conformi_chain = k_totale_chain - k_invalide_chain

        r.record("k_totale_chain_vs_record_chiusura", closure.k_totale == k_totale_chain)
        r.record("k_totale_doc_vs_chain", doc.k_totale == k_totale_chain)
        r.record("k_invalide_doc_vs_chain", doc.k_invalide == k_invalide_chain)
        r.record("k_conformi_doc_vs_chain", doc.k_conformi == k_conformi_chain)
        r.record("equazione_coerenza_numerica", doc.k_conformi + doc.k_invalide == doc.k_totale)
        r.record("risultato_lunghezza_N", len(doc.risultato) == self._params.n_opzioni)
        r.record("somma_risultato_uguale_k_conformi", sum(doc.risultato) == doc.k_conformi)

        # ---- corrispondenza Invalid_j <-> Record_j effettivi -----------
        vote_by_j = {b.j: b for b in chain if isinstance(b, VoteRecord)}
        inv_js: list[int] = []
        inv_ok = True
        for b in chain:
            if isinstance(b, InvalidRecord):
                inv_js.append(b.j)
                vr = vote_by_j.get(b.j)
                if (vr is None or vr.k_j != b.k_j or b.motivo not in MOTIVI_VALIDI
                        or b.id_elezione != self._params.id_elezione):
                    inv_ok = False
        if len(set(inv_js)) != len(inv_js):
            inv_ok = False
            r.notes.append("indici j duplicati tra i record Invalid_j")
        r.record("invalid_j_corrispondono_a_record_j", inv_ok)

        return r
