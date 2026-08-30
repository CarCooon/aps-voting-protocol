"""Autorita' Elettorale (AE).

Riceve, ordina e conserva le schede protette; a chiusura esegue lo scrutinio
black-box.

Ricezione - 5 controlli sequenziali, esito binario:
  1. finestra temporale   t_apertura <= now <= t_chiusura   (confronto reale)
  2. autorizzazione       verifica Sign_PR_SA su C_p  +  C_p.id == M.id == elezione corrente
  3. unicita'             PU_v non in Registro_Effimeri_AE
  4. anti-replay          eta non in Registro_Nonce_AE
  5. integrita'           verifica sigma con PU_v ESTRATTA DA C_p
Iscrizione nei registri solo in caso di accettazione.  Il ciphertext C_j viene
decifrato solo allo scrutinio, quindi dopo che sigma e' stata verificata al
controllo 5: verifica dell'autenticita' prima della decifratura, come nelle
esercitazioni su Encrypt-then-MAC e cifratura ibrida.

Scrutinio - richiede PR_ele, che NON e' nel costruttore dell'AE: viene iniettata
da un KeyCustodian solo a partire da t_chiusura (`activate_tally_key`), modellando
la custodia offline della chiave di scrutinio.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from . import crypto
from .crypto import VOTE_INT_WIDTH
from .messages import (
    MOTIVO_DECRYPT_FAILED,
    MOTIVO_MALFORMED_PADDING,
    MOTIVO_OUT_OF_RANGE,
    BallotPacket,
    ElectionParams,
    FinalDocument,
    Receipt,
)
from .urn import PublicUrn


class BallotRejected(Exception):
    """Un pacchetto M non ha superato un controllo alla ricezione.
    `check`: 1..5 per i cinque controlli sequenziali, 0 se il pacchetto non e'
    nemmeno decodificabile."""

    def __init__(self, check: int, reason: str) -> None:
        super().__init__(f"[Controllo {check}] {reason}")
        self.check = check
        self.reason = reason


class TallyKeyError(Exception):
    """Tentativo di attivare/rilasciare PR_ele prima di t_chiusura o a urna aperta."""


@dataclass
class _ArchivedBallot:
    j: int
    c: bytes
    eta: bytes
    k_j: bytes
    f_j: bytes


class KeyCustodian:
    """Custode offline di PR_ele.  Consegna la chiave solo a partire da t_chiusura."""

    def __init__(self, pr_ele: RSAPrivateKey, params: ElectionParams, clock=time.time) -> None:
        self._pr_ele = pr_ele
        self._params = params
        self._clock = clock
        self.released = False

    def release(self) -> RSAPrivateKey:
        if self._clock() < self._params.t_chiusura:
            raise TallyKeyError("PR_ele non disponibile prima di t_chiusura")
        self.released = True
        return self._pr_ele


class ElectoralAuthority:
    def __init__(self, params: ElectionParams, pu_ele: RSAPublicKey, pu_sa: RSAPublicKey, clock=time.time) -> None:
        self.params = params
        self._pu_ele = pu_ele
        self._pu_sa = pu_sa
        self._clock = clock
        self._priv_ae, self.public_key = crypto.generate_rsa_keypair()

        # Urna pubblica (contiene Record_0).  La vista pubblica e' cio' che SA /
        # Verificatore / elettori osservano.
        self.urn = PublicUrn(params, pu_ele, self._priv_ae, self.public_key)

        # Registri interni dell'AE (mai condivisi con il SA).
        self._ephemeral_register: set[str] = set()   # fingerprint di PU_v gia' usate
        self._nonce_register: set[bytes] = set()      # eta gia' visti
        self._archive: dict[int, _ArchivedBallot] = {}  # j -> (C_j, eta_j, K_j, F_j)
        self._next_j = 1

        # PR_ele assente finche' non attivata (iniezione tardiva).
        self._pr_ele: RSAPrivateKey | None = None

    # ------------------------------------------------------ ricezione della scheda
    def receive_ballot(self, packet: BallotPacket | bytes) -> Receipt:
        """Applica i 5 controlli sequenziali; se superati registra il voto,
        bufferizza il Record_j e restituisce la ricevuta R firmata."""
        if isinstance(packet, BallotPacket):
            m = packet
        else:
            try:
                m = BallotPacket.from_wire(packet)
            except (ValueError, TypeError) as exc:
                raise BallotRejected(0, f"pacchetto M non decodificabile: {exc}") from exc

        # --- Controllo 1: finestra temporale (confronto reale con l'orologio) ---
        now = self._clock()
        if now < self.params.t_apertura:
            raise BallotRejected(1, "pacchetto ricevuto prima di t_apertura")
        if now > self.params.t_chiusura:
            raise BallotRejected(1, "pacchetto ricevuto dopo t_chiusura")

        # --- Controllo 2: autorizzazione (firma SA su C_p + coerenza id_elezione) ---
        cert = m.cert
        if not cert.verify(self._pu_sa):
            raise BallotRejected(2, "firma del SA su C_p non valida")
        if cert.id_elezione != self.params.id_elezione:
            raise BallotRejected(2, "C_p emesso per un'altra elezione")
        if m.id_elezione != self.params.id_elezione:
            raise BallotRejected(2, "id_elezione del pacchetto M diverso dall'elezione corrente")

        # --- Controllo 3: unicita' di PU_v ---
        pu_v_fp = crypto.sha256_hex(cert.pu_v_der)
        if pu_v_fp in self._ephemeral_register:
            raise BallotRejected(3, "PU_v gia' nel Registro_Effimeri_AE (doppio voto)")

        # --- Controllo 4: anti-replay sul nonce eta ---
        if m.eta in self._nonce_register:
            raise BallotRejected(4, "eta gia' nel Registro_Nonce_AE (replay)")

        # --- Controllo 5: integrita' di sigma con PU_v estratta DA C_p ---
        try:
            pu_v = cert.pu_v()
        except (ValueError, TypeError) as exc:  # DER corrotto o chiave non RSA in C_p
            raise BallotRejected(5, f"PU_v in C_p non decodificabile: {exc}") from exc
        if not m.verify_sigma(pu_v):
            raise BallotRejected(5, "firma effimera sigma non valida (pacchetto alterato)")

        # --- Accettazione: registrazione (solo ora) + buffer + ricevuta ---
        j = self._next_j
        self._next_j += 1
        k_j = crypto.sha256(m.c)
        f_j = crypto.sha256(k_j + m.eta)

        self._ephemeral_register.add(pu_v_fp)
        self._nonce_register.add(m.eta)
        self._archive[j] = _ArchivedBallot(j, m.c, m.eta, k_j, f_j)
        self.urn.buffer_record(j, k_j, f_j)

        return Receipt.create(k_j, f_j, j, self.params.id_elezione, self._priv_ae)

    def flush_window(self):
        return self.urn.flush_window()

    # ------------------------------------------------------------- chiusura dell'urna
    def close(self):
        """A t_chiusura: stop accettazione, ultimo flush, Record_chiusura."""
        if self._clock() < self.params.t_chiusura:
            raise RuntimeError("chiusura richiesta prima di t_chiusura")
        return self.urn.close()

    # ------------------------------------------------------------------- scrutinio
    def activate_tally_key(self, custodian: KeyCustodian) -> None:
        """Iniezione tardiva di PR_ele.  Rifiuta se l'urna non e' chiusa o now < t_chiusura."""
        if not self.urn.closed:
            raise TallyKeyError("l'urna non e' ancora chiusa: PR_ele non attivabile")
        if self._clock() < self.params.t_chiusura:
            raise TallyKeyError("PR_ele non attivabile prima di t_chiusura")
        self._pr_ele = custodian.release()

    def tally(self) -> FinalDocument:
        """Scrutinio black-box: decifra ogni C_j con PR_ele, controlla il dominio
        1 <= i <= N, accoda Invalid_j per le schede non conformi, pubblica
        Doc_finale.  I singoli plaintext NON sono memorizzati ne' ricollegati a F_j."""
        if self._pr_ele is None:
            raise TallyKeyError("PR_ele non attivata")

        n = self.params.n_opzioni
        risultato = [0] * n
        k_conformi = k_invalide = 0

        for j in sorted(self._archive):
            ab = self._archive[j]
            motivo: str | None = None
            try:
                plaintext = crypto.oaep_decrypt(self._pr_ele, ab.c)
            except ValueError:
                motivo = MOTIVO_DECRYPT_FAILED
            else:
                if len(plaintext) != VOTE_INT_WIDTH:
                    motivo = MOTIVO_MALFORMED_PADDING
                else:
                    i = int.from_bytes(plaintext, "big")
                    if 1 <= i <= n:
                        risultato[i - 1] += 1
                        k_conformi += 1
                    else:
                        motivo = MOTIVO_OUT_OF_RANGE
            if motivo is not None:
                self.urn.append_invalid(j, ab.k_j, motivo)
                k_invalide += 1

        k_totale = len(self._archive)
        if k_conformi + k_invalide != k_totale:
            raise RuntimeError("coerenza numerica interna violata")

        doc = FinalDocument.create(
            tuple(risultato), k_totale, k_conformi, k_invalide,
            self.urn.final_root_bytes(), self._priv_ae,
        )
        self.urn.publish_final_document(doc)
        return doc

    def view(self):
        return self.urn.view()
