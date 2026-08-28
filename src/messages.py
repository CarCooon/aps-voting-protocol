"""Strutture dati del protocollo di voto elettronico.

Ogni struttura firmata espone:
  - `signed_bytes()`  : i byte canonici (via `crypto.wire`) su cui si calcola la
                        firma; e' l'argomento di H(.) e include TUTTI i campi della
                        tupla TRANNE la firma.
  - `verify(pubkey)`  : True se la firma e' valida sotto la chiave data.
I blocchi della hash chain espongono inoltre:
  - `block_digest()`  : H(Record_j), hash dell'intero blocco (firma inclusa), usato
                        come hash pointer dal blocco successivo.

Scelte di codifica:
  * Sign_PR(H(x)) e' istanziato con RSA-PSS su x (SHA-256 interno, un solo hash).
  * `Invalid_j`: il digest firmato include anche l'hash pointer H(Record_prec),
    coerentemente con `Record_j` che firma gia' il proprio hash pointer: poiche'
    `Invalid_j` E' un blocco della catena, senza questo un terzo potrebbe
    ri-agganciarlo altrove senza invalidare alcuna firma.
  * I timestamp entrano nelle strutture firmate come interi (microsecondi epoch).
  * Le Merkle Root sono firmate da AE e SA sul SOLO valore della radice (32 byte);
    `window_index` e `leaf_count` restano metadati non firmati.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from . import crypto
from .crypto import unwire, wire

# Codici `motivo` per i record Invalid_j (assegnati a scrutinio).
MOTIVO_OUT_OF_RANGE = "OUT_OF_RANGE"            # i decifrato ma i < 1 o i > N
MOTIVO_DECRYPT_FAILED = "DECRYPT_FAILED"        # RSA-OAEP-Dec fallita (C non cifrato con PU_ele)
MOTIVO_MALFORMED_PADDING = "MALFORMED_PADDING"  # plaintext decifrato ma di lunghezza != VOTE_INT_WIDTH
MOTIVI_VALIDI = frozenset({MOTIVO_OUT_OF_RANGE, MOTIVO_DECRYPT_FAILED, MOTIVO_MALFORMED_PADDING})


def ts_to_int(t: float) -> int:
    """Timestamp epoch (secondi, float) -> intero (microsecondi) per la firma."""
    return int(round(t * 1_000_000))


# ===========================================================================
#  Params (contenuto del blocco genesi Record_0)
# ===========================================================================
@dataclass(frozen=True)
class ElectionParams:
    """Params = { id_elezione, PU_ele, N, lista_candidati, t_apertura, t_chiusura }.
    Elezione a lista chiusa con N opzioni; il referendum binario e' il caso N = 2.
    Il voto e' un intero scalare i in {1..N}."""

    id_elezione: str
    n_opzioni: int
    lista_candidati: tuple[str, ...]
    t_apertura: float
    t_chiusura: float

    def __post_init__(self) -> None:
        if self.n_opzioni < 2:
            raise ValueError("N deve essere >= 2 (lista chiusa; N=2 e' il referendum binario)")
        if len(self.lista_candidati) != self.n_opzioni:
            raise ValueError("len(lista_candidati) deve essere uguale a N")
        if self.t_chiusura <= self.t_apertura:
            raise ValueError("t_chiusura deve essere successivo a t_apertura")


# ===========================================================================
#  Record_0 (blocco genesi)
# ===========================================================================
@dataclass(frozen=True)
class GenesisRecord:
    """Record_0 = { Params, Sign_PR_AE(H(Params)) }.  Non contiene alcun voto:
    e' l'ancoraggio della hash chain."""

    id_elezione: str
    pu_ele_der: bytes
    n_opzioni: int
    lista_candidati: tuple[str, ...]
    t_apertura: float
    t_chiusura: float
    signature: bytes

    def signed_bytes(self) -> bytes:
        return wire([
            self.id_elezione, self.pu_ele_der, self.n_opzioni,
            list(self.lista_candidati), ts_to_int(self.t_apertura), ts_to_int(self.t_chiusura),
        ])

    @classmethod
    def create(cls, params: ElectionParams, pu_ele: RSAPublicKey, pr_ae: RSAPrivateKey) -> "GenesisRecord":
        rec = cls(
            params.id_elezione, crypto.public_key_to_der(pu_ele), params.n_opzioni,
            params.lista_candidati, params.t_apertura, params.t_chiusura, b"",
        )
        return _resign(rec, pr_ae)

    def verify(self, pu_ae: RSAPublicKey) -> bool:
        return crypto.verify(pu_ae, self.signed_bytes(), self.signature)

    def block_digest(self) -> bytes:
        return crypto.sha256(wire([self.signed_bytes(), self.signature]))


# ===========================================================================
#  Certificato pseudonimo C_p
# ===========================================================================
@dataclass(frozen=True)
class Certificate:
    """C_p = { PU_v, id_elezione, Sign_PR_SA(H(PU_v || id_elezione)) }.
    Non contiene in alcun campo l'identita' reale dell'elettore."""

    pu_v_der: bytes
    id_elezione: str
    signature: bytes

    def signed_bytes(self) -> bytes:
        return wire([self.pu_v_der, self.id_elezione])

    @classmethod
    def create(cls, pu_v: RSAPublicKey, id_elezione: str, pr_sa: RSAPrivateKey) -> "Certificate":
        return _resign(cls(crypto.public_key_to_der(pu_v), id_elezione, b""), pr_sa)

    def verify(self, pu_sa: RSAPublicKey) -> bool:
        return crypto.verify(pu_sa, self.signed_bytes(), self.signature)

    def pu_v(self) -> RSAPublicKey:
        """Estrae PU_v DAL certificato firmato: la chiave con cui si verifica sigma
        va presa da C_p, non fuori banda."""
        return crypto.public_key_from_der(self.pu_v_der)

    def wire_bytes(self) -> bytes:
        """Serializzazione completa di C_p (firma inclusa): entra nel digest di M."""
        return wire([self.pu_v_der, self.id_elezione, self.signature])

    @classmethod
    def from_wire(cls, buf: bytes) -> "Certificate":
        pu_v_der, id_elezione, signature = unwire(buf)
        return cls(pu_v_der, id_elezione, signature)


# ===========================================================================
#  Pacchetto di voto M
# ===========================================================================
@dataclass(frozen=True)
class BallotPacket:
    """M = (C, C_p, eta, id_elezione, sigma)  con
    sigma = Sign_PR_v(H(C || C_p || eta || id_elezione))   (Encrypt-then-Sign).
    C_p e' incluso DENTRO il digest firmato da sigma (difesa dalla sostituzione
    del mittente)."""

    c: bytes
    cert: Certificate
    eta: bytes
    id_elezione: str
    sigma: bytes

    def signed_bytes(self) -> bytes:
        return wire([self.c, self.cert.wire_bytes(), self.eta, self.id_elezione])

    @classmethod
    def create(cls, c: bytes, cert: Certificate, eta: bytes, id_elezione: str, pr_v: RSAPrivateKey) -> "BallotPacket":
        m = cls(c, cert, eta, id_elezione, b"")
        return cls(c, cert, eta, id_elezione, crypto.sign(pr_v, m.signed_bytes()))

    def verify_sigma(self, pu_v: RSAPublicKey) -> bool:
        return crypto.verify(pu_v, self.signed_bytes(), self.sigma)

    def wire_bytes(self) -> bytes:
        return wire([self.c, self.cert.wire_bytes(), self.eta, self.id_elezione, self.sigma])

    @classmethod
    def from_wire(cls, buf: bytes) -> "BallotPacket":
        c, cert_wire, eta, id_elezione, sigma = unwire(buf)
        return cls(c, Certificate.from_wire(cert_wire), eta, id_elezione, sigma)


# ===========================================================================
#  Ricevuta R
# ===========================================================================
@dataclass(frozen=True)
class Receipt:
    """R = ( K_j, F_j, j, id_elezione, Sign_PR_AE(H(K_j || F_j || j || id_elezione)) )."""

    k_j: bytes
    f_j: bytes
    j: int
    id_elezione: str
    signature: bytes

    def signed_bytes(self) -> bytes:
        return wire([self.k_j, self.f_j, self.j, self.id_elezione])

    @classmethod
    def create(cls, k_j: bytes, f_j: bytes, j: int, id_elezione: str, pr_ae: RSAPrivateKey) -> "Receipt":
        return _resign(cls(k_j, f_j, j, id_elezione, b""), pr_ae)

    def verify(self, pu_ae: RSAPublicKey) -> bool:
        return crypto.verify(pu_ae, self.signed_bytes(), self.signature)

    def wire_bytes(self) -> bytes:
        return wire([self.k_j, self.f_j, self.j, self.id_elezione, self.signature])


# ===========================================================================
#  Urna - Record_j della hash chain
# ===========================================================================
@dataclass(frozen=True)
class VoteRecord:
    """Record_j = { j, K_j, F_j, H(Record_{j-1}),
                    Sign_PR_AE(H(j || K_j || F_j || H(Record_{j-1}))) }.
    L'urna pubblica NON contiene C_j: solo K_j = H(C_j) e F_j = H(K_j || eta_j)."""

    j: int
    k_j: bytes
    f_j: bytes
    prev_hash: bytes
    signature: bytes

    def signed_bytes(self) -> bytes:
        return wire([self.j, self.k_j, self.f_j, self.prev_hash])

    @classmethod
    def create(cls, j: int, k_j: bytes, f_j: bytes, prev_hash: bytes, pr_ae: RSAPrivateKey) -> "VoteRecord":
        return _resign(cls(j, k_j, f_j, prev_hash, b""), pr_ae)

    def verify(self, pu_ae: RSAPublicKey) -> bool:
        return crypto.verify(pu_ae, self.signed_bytes(), self.signature)

    def block_digest(self) -> bytes:
        return crypto.sha256(wire([self.signed_bytes(), self.signature]))


# ===========================================================================
#  Scrutinio - Invalid_j accodato alla hash chain
# ===========================================================================
@dataclass(frozen=True)
class InvalidRecord:
    """Invalid_j = { id_elezione, j, K_j, motivo, H(Record_prec),
                     Sign_PR_AE(H(id_elezione || j || K_j || motivo || H(Record_prec))) }.
    Una scheda fuori range o malformata NON viene rimossa: viene etichettata con
    un record firmato e accodata alla catena."""

    id_elezione: str
    j: int
    k_j: bytes
    motivo: str
    prev_hash: bytes
    signature: bytes

    def signed_bytes(self) -> bytes:
        return wire([self.id_elezione, self.j, self.k_j, self.motivo, self.prev_hash])

    @classmethod
    def create(cls, id_elezione: str, j: int, k_j: bytes, motivo: str, prev_hash: bytes, pr_ae: RSAPrivateKey) -> "InvalidRecord":
        return _resign(cls(id_elezione, j, k_j, motivo, prev_hash, b""), pr_ae)

    def verify(self, pu_ae: RSAPublicKey) -> bool:
        return crypto.verify(pu_ae, self.signed_bytes(), self.signature)

    def block_digest(self) -> bytes:
        return crypto.sha256(wire([self.signed_bytes(), self.signature]))


# ===========================================================================
#  Record_chiusura
# ===========================================================================
@dataclass(frozen=True)
class ClosureRecord:
    """Record_chiusura = { k_totale, MerkleRoot_finale, H(Record_n),
                           Sign_PR_AE(H(k_totale || MerkleRoot_finale || H(Record_n))) }."""

    k_totale: int
    merkle_root_finale: bytes
    prev_hash: bytes
    signature: bytes

    def signed_bytes(self) -> bytes:
        return wire([self.k_totale, self.merkle_root_finale, self.prev_hash])

    @classmethod
    def create(cls, k_totale: int, merkle_root_finale: bytes, prev_hash: bytes, pr_ae: RSAPrivateKey) -> "ClosureRecord":
        return _resign(cls(k_totale, merkle_root_finale, prev_hash, b""), pr_ae)

    def verify(self, pu_ae: RSAPublicKey) -> bool:
        return crypto.verify(pu_ae, self.signed_bytes(), self.signature)

    def block_digest(self) -> bytes:
        return crypto.sha256(wire([self.signed_bytes(), self.signature]))


# ===========================================================================
#  Merkle Root co-firmata (AE + SA)
# ===========================================================================
@dataclass(frozen=True)
class CoSignedRoot:
    """Merkle Root pubblicata e controfirmata.  La co-firma del SA e' una difesa
    strutturale sempre attiva: senza la complicita' del SA l'AE non puo' presentare
    agli elettori una storia dell'urna alternativa e coerente.

    Sia l'AE sia il SA firmano il SOLO valore della radice (32 byte).
    `window_index` e `leaf_count` sono metadati NON firmati (identificazione della
    finestra e sanity-check di monotonia); il conteggio autoritativo delle foglie
    e' `k_totale` nel Record_chiusura firmato.  Il verificatore controlla ENTRAMBE
    le firme."""

    window_index: int
    root: bytes
    leaf_count: int
    ae_signature: bytes
    sa_signature: bytes | None  # None finche' il SA non ha co-firmato

    def signed_bytes(self) -> bytes:
        return self.root

    @classmethod
    def create_ae(cls, window_index: int, root: bytes, leaf_count: int, pr_ae: RSAPrivateKey) -> "CoSignedRoot":
        return cls(window_index, root, leaf_count, crypto.sign(pr_ae, root), None)

    def with_sa_signature(self, pr_sa: RSAPrivateKey) -> "CoSignedRoot":
        return CoSignedRoot(self.window_index, self.root, self.leaf_count,
                            self.ae_signature, crypto.sign(pr_sa, self.root))

    def verify_ae(self, pu_ae: RSAPublicKey) -> bool:
        return crypto.verify(pu_ae, self.root, self.ae_signature)

    def verify_sa(self, pu_sa: RSAPublicKey) -> bool:
        return self.sa_signature is not None and crypto.verify(pu_sa, self.root, self.sa_signature)


# ===========================================================================
#  Documento di scrutinio finale
# ===========================================================================
@dataclass(frozen=True)
class FinalDocument:
    """Doc_finale = { Risultato, k_totale, k_conformi, k_invalide, Merkle_Root_finale,
                      Sign_PR_AE(H(Risultato || k_totale || k_conformi || k_invalide || Merkle_Root_finale)) }.

    Risultato[k] = |{ j : i_j = k }|, k in 1..N.  I singoli plaintext i_j NON sono
    pubblicati ne' ricollegati a F_j."""

    risultato: tuple[int, ...]
    k_totale: int
    k_conformi: int
    k_invalide: int
    merkle_root_finale: bytes
    signature: bytes

    def signed_bytes(self) -> bytes:
        return wire([list(self.risultato), self.k_totale, self.k_conformi, self.k_invalide, self.merkle_root_finale])

    @classmethod
    def create(cls, risultato: tuple[int, ...], k_totale: int, k_conformi: int, k_invalide: int,
               merkle_root_finale: bytes, pr_ae: RSAPrivateKey) -> "FinalDocument":
        doc = cls(risultato, k_totale, k_conformi, k_invalide, merkle_root_finale, b"")
        return _resign(doc, pr_ae)

    def verify(self, pu_ae: RSAPublicKey) -> bool:
        return crypto.verify(pu_ae, self.signed_bytes(), self.signature)


# --------------------------------------------------------------------------- util
def _resign(obj, priv: RSAPrivateKey):
    """Restituisce una copia di `obj` (dataclass frozen con campo `signature`) con
    la firma calcolata su `signed_bytes()`.  Evita di ripetere lo stesso schema in
    ogni `create`."""
    return dataclasses.replace(obj, signature=crypto.sign(priv, obj.signed_bytes()))
