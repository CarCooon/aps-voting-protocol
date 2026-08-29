"""Elettore.

  Autenticazione: genera la coppia effimera (PU_v, PR_v); si autentica via SSO/MFA
      presso l'IdP; ottiene la challenge dal SA e ne firma l'hash con PR_v
      (proof-of-possession); riceve e verifica C_p.
  Costruzione della scheda: codifica il voto come intero scalare i in {1..N}, lo
      cifra con RSA-OAEP, genera il nonce eta, firma il pacchetto
      (Encrypt-then-Sign) -> M.
  Ricezione: riceve la ricevuta R e ne VERIFICA la firma dell'AE PRIMA di
      cancellare il materiale effimero (PR_v).  Il fattore r di OAEP non e'
      cancellabile esplicitamente: e' interno a `cryptography` e mai esposto
      (soddisfatto per costruzione).  Il ciphertext C si conserva: serve alla
      verifica individuale.
  Verifica individuale: ricalcola K=H(C) e F=H(K||eta), verifica ENTRAMBE le firme
      (AE e SA) sulla Root definitiva co-firmata, ottiene la Merkle proof e la
      valida.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from . import crypto
from .crypto import VOTE_INT_WIDTH
from .messages import BallotPacket, Certificate, ElectionParams, Receipt, VoteRecord


class VoterError(Exception):
    pass


class Voter:
    def __init__(self, subject_id: str, params: ElectionParams,
                 pu_ele: RSAPublicKey, pu_sa: RSAPublicKey, pu_ae: RSAPublicKey) -> None:
        self.subject_id = subject_id
        self._params = params
        self._pu_ele = pu_ele
        self._pu_sa = pu_sa
        self._pu_ae = pu_ae

        # Materiale effimero dell'autenticazione.  PR_v verra' cancellato dopo la
        # verifica di R.
        self._pr_v: RSAPrivateKey | None = None
        self._pu_v: RSAPublicKey | None = None
        self.cert: Certificate | None = None

        # Dati conservati per la verifica individuale.
        self.c: bytes | None = None
        self.eta: bytes | None = None
        self.receipt: Receipt | None = None
        self.j: int | None = None
        # Annotazione per scenari/benchmark: la preferenza scelta.  Non e' materiale
        # da cancellare (si cancellano PR_v e r, non i): senza r non consente di
        # ricalcolare C, quindi da sola non e' una prova del voto.
        self.chosen_i: int | None = None

    # ------------------------------------------------------------- autenticazione
    def start_session(self) -> None:
        self._pr_v, self._pu_v = crypto.generate_rsa_keypair()

    def authenticate(self, idp, sa, present_mfa: bool = True) -> Certificate:
        """SSO/MFA presso l'IdP -> challenge-response col SA -> emissione di C_p."""
        if self._pr_v is None or self._pu_v is None:
            raise VoterError("start_session() non chiamato")

        id_token = idp.authenticate(self.subject_id, self._params.id_elezione, present_mfa=present_mfa)
        pu_v_der = crypto.public_key_to_der(self._pu_v)

        nonce = sa.request_challenge(id_token, pu_v_der)
        pop_sig = crypto.sign(self._pr_v, nonce)  # Sign_PR_v(H(nonce))
        cert = sa.issue_certificate(id_token, pu_v_der, pop_sig)

        if not cert.verify(self._pu_sa):
            raise VoterError("C_p ricevuto con firma SA non valida")
        if cert.id_elezione != self._params.id_elezione:
            raise VoterError("C_p emesso per un'altra elezione")
        self.cert = cert
        return cert

    # ------------------------------------------------------ costruzione della scheda
    def build_ballot(self, i: int) -> BallotPacket:
        """Costruisce M = (C, C_p, eta, id, sigma).  Nessun vincolo di range imposto
        qui: il controllo 1<=i<=N e' allo scrutinio."""
        if self.cert is None or self._pr_v is None:
            raise VoterError("autenticazione non completata")

        # Encrypt-then-Sign (come nell'esercitazione sulla cifratura ibrida):
        # si cifra il voto con RSA-OAEP, poi si firma l'intero pacchetto.
        i_bytes = int(i).to_bytes(VOTE_INT_WIDTH, "big")
        c = crypto.oaep_encrypt(self._pu_ele, i_bytes)   # C = RSA-OAEP-Enc(PU_ele, i; r)
        eta = crypto.fresh_nonce()                       # eta <- CSPRNG(256)
        m = BallotPacket.create(c, self.cert, eta, self._params.id_elezione, self._pr_v)

        self.c = c
        self.eta = eta
        self.chosen_i = i
        return m

    # ---------------------------------------------------- ricezione della ricevuta
    def process_receipt(self, receipt: Receipt) -> None:
        """Verifica la firma dell'AE su R, ne controlla la coerenza con i dati
        locali e SOLO ALLORA cancella il materiale effimero (PR_v)."""
        if self.c is None or self.eta is None:
            raise VoterError("nessuna scheda costruita")

        if not receipt.verify(self._pu_ae):
            raise VoterError("firma dell'AE sulla ricevuta R non valida: PR_v NON cancellato")

        k = crypto.sha256(self.c)
        f = crypto.sha256(k + self.eta)
        if receipt.k_j != k or receipt.f_j != f:
            raise VoterError("R incoerente con K/F ricalcolati localmente")
        if receipt.id_elezione != self._params.id_elezione or receipt.j < 1:
            raise VoterError("campi di R non validi")

        self.receipt = receipt
        self.j = receipt.j

        # Cancellazione sicura del materiale effimero: PR_v.  Il fattore r di OAEP
        # non e' mai esposto dalla libreria -> soddisfatto per costruzione.
        self._pr_v = None
        self._pu_v = None

    @property
    def ephemeral_private_key_wiped(self) -> bool:
        return self._pr_v is None

    # ------------------------------------------------------- verifica individuale
    def verify_individual_inclusion(self, urn_view) -> bool:
        """Verifica individuale sui dati locali (C, eta, R) + vista pubblica
        dell'urna.  True solo se ogni passo ha successo."""
        if self.receipt is None or self.c is None or self.eta is None or self.j is None:
            raise VoterError("prerequisiti della verifica individuale mancanti")

        # (1)-(2) ricalcolo commitment e fingerprint
        k = crypto.sha256(self.c)
        f = crypto.sha256(k + self.eta)
        if f != self.receipt.f_j:
            return False

        # Root definitiva co-firmata: ENTRAMBE le firme (AE e SA) devono valere.
        try:
            cosigned = urn_view.final_cosigned_root()
        except RuntimeError:
            return False  # nessuna Root definitiva co-firmata coerente col Record_chiusura
        if not cosigned.verify_ae(self._pu_ae) or not cosigned.verify_sa(self._pu_sa):
            return False

        # (3) Merkle proof contro la Root definitiva
        try:
            proof, root = urn_view.merkle_proof_for(f)
        except (KeyError, ValueError):
            return False  # fingerprint assente: scheda omessa/rimossa
        if root != cosigned.root or not urn_view.verify_membership(f, proof, root):
            return False

        # (4) controllo aggiuntivo: coerenza con il Record_j pubblicato nella hash chain
        for block in urn_view.chain():
            if isinstance(block, VoteRecord) and block.j == self.j:
                return block.k_j == k and block.f_j == f
        return False
