"""Orchestratore dell'elezione simulata.

Cabla i quattro attori (Elettore, SA, AE, Verificatore Pubblico) piu' le
astrazioni dichiarate (PKI, IdP, canale "TLS", orologio -> modulo `sim`) e offre
un'API lineare a scenari e test.

Distribuzione delle chiavi: tutte le chiavi pubbliche sono autenticate dalla CA
(`sim.CertificateAuthority`) e i canali verso i server sono "aperti" verificando
il relativo certificato X.509, come farebbe un client TLS.

Non-collusione SA/AE: l'orchestratore non passa MAI dati privati dall'AE al SA.
La co-firma delle Root avviene via `sa.cosign_roots(ae.view())`, cioe' leggendo
la sola vista pubblica dell'urna.

Nessuna metrica in questo modulo: gli scenari misurano esternamente con
`time.perf_counter`, in variabili locali.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from . import crypto
from .ae import ElectoralAuthority, KeyCustodian
from .messages import BallotPacket, ElectionParams, Receipt
from .sa import AuthServer
from .sim import CertificateAuthority, IdentityProvider, SimClock, open_tls_channel
from .verifier import PublicVerifier, VerificationReport
from .voter import Voter


def demo_parameters(id_elezione: str = "unisa-cds-2026", n_opzioni: int = 4,
                    window_seconds: int = 3600, now: float | None = None) -> ElectionParams:
    """Parametri di comodo per prototipo/benchmark: finestra centrata su `now`."""
    base = time.time() if now is None else now
    return ElectionParams(
        id_elezione=id_elezione,
        n_opzioni=n_opzioni,
        lista_candidati=tuple(f"Lista {chr(ord('A') + k)}" for k in range(n_opzioni)),
        t_apertura=base - 1.0,
        t_chiusura=base + window_seconds,
    )


@dataclass
class Election:
    """Ambiente di elezione completo: attori, PKI simulata e orologio gia' cablati."""

    params: ElectionParams
    clock: SimClock

    ca: CertificateAuthority = field(init=False)
    idp: IdentityProvider = field(init=False)
    sa: AuthServer = field(init=False)
    ae: ElectoralAuthority = field(init=False)
    verifier: PublicVerifier = field(init=False)
    pu_ele: RSAPublicKey = field(init=False)
    _pr_ele: RSAPrivateKey = field(init=False)
    custodian: KeyCustodian = field(init=False)
    window_size: int = field(init=False, default=0)
    _since_flush: int = field(init=False, default=0)

    # ----------------------------------------- allestimento (attori, chiavi, PKI)
    @classmethod
    def setup(cls, params: ElectionParams | None = None, clock: SimClock | None = None,
              window_size: int = 0) -> "Election":
        clk = clock or SimClock()
        prm = params or demo_parameters(now=clk())
        e = cls(params=prm, clock=clk)

        e.ca = CertificateAuthority(clock=clk)
        e.idp = IdentityProvider(clock=clk)

        # (PU_ele, PR_ele): PR_ele NON e' data all'AE ma affidata al KeyCustodian.
        e._pr_ele, e.pu_ele = crypto.generate_rsa_keypair()
        e.custodian = KeyCustodian(e._pr_ele, prm, clock=clk)

        e.sa = AuthServer(prm.id_elezione, e.idp.public_key, clock=clk)
        e.ae = ElectoralAuthority(prm, e.pu_ele, e.sa.public_key, clock=clk)
        e.verifier = PublicVerifier(prm, e.sa.public_key)

        # Distribuzione autenticata delle chiavi pubbliche (PKI/X.509 simulata):
        # ogni "connessione" verso un server verifica il suo certificato X.509.
        for name, key in (("AE", e.ae.public_key), ("SA", e.sa.public_key),
                          ("IdP", e.idp.public_key), ("ELE", e.pu_ele)):
            open_tls_channel(e.ca, name, e.ca.issue(name, key))

        e.window_size = window_size
        e._since_flush = 0
        return e

    # ------------------------------------------------------ registrazione utenti
    def enroll(self, subject_id: str, eligible: bool = True, has_mfa: bool = True) -> None:
        elections = {self.params.id_elezione} if eligible else set()
        self.idp.register_student(subject_id, elections, has_mfa=has_mfa)

    def new_voter(self, subject_id: str) -> Voter:
        return Voter(subject_id, self.params, self.pu_ele, self.sa.public_key, self.ae.public_key)

    # ------------------------------------ autenticazione dell'elettore ed emissione C_p
    def authenticate(self, voter: Voter, present_mfa: bool = True) -> None:
        voter.start_session()
        voter.authenticate(self.idp, self.sa, present_mfa=present_mfa)

    # ------------------------------------------- invio della scheda e ricevuta
    def cast_vote(self, voter: Voter, preference: int, tamper=None) -> Receipt:
        """Costruzione di M, invio all'AE, ricezione e verifica della ricevuta R.

        Il pacchetto M e' serializzato in forma binaria, eventualmente alterato da
        un MITM (`tamper: callable(bytes)->bytes`) "in transito", e consegnato
        all'AE come byte grezzi: un attacco di rete opera cosi' sui byte reali e
        non sull'oggetto Python, e la deserializzazione la fa l'AE.  Restituisce la
        ricevuta R (gia' verificata dall'elettore)."""
        m = voter.build_ballot(preference)
        on_wire = m.wire_bytes()
        if tamper is not None:
            on_wire = tamper(on_wire)
        receipt = self.ae.receive_ballot(on_wire)
        voter.process_receipt(receipt)
        return self._after_receive(receipt)

    def submit_packet(self, m: BallotPacket) -> Receipt:
        """Invio diretto di un M gia' costruito, senza la verifica lato elettore.
        Lo usano gli scenari che partono da un pacchetto costruito ad arte
        (certificato contraffatto, nonce riusato, firma non valida)."""
        return self._after_receive(self.ae.receive_ballot(m.wire_bytes()))

    def _after_receive(self, receipt: Receipt) -> Receipt:
        """Contabilizza una scheda accettata e, se la finestra e' piena, la pubblica."""
        self._since_flush += 1
        if self.window_size and self._since_flush >= self.window_size:
            self.flush_window()
        return receipt

    # ---------------------------------------------------- pubblicazione per finestre
    def flush_window(self) -> None:
        self.ae.flush_window()
        self._since_flush = 0
        self._sync_cosign()

    def _sync_cosign(self) -> None:
        """Il SA legge le Root dalla vista pubblica dell'urna e le co-firma."""
        cosigned = self.sa.cosign_roots(self.ae.view())
        if cosigned:
            self.ae.urn.attach_cosigned_roots(cosigned)

    # ----------------------------------------------------- chiusura e scrutinio
    def close_and_tally(self):
        """Chiusura dell'urna, co-firma della Root definitiva e scrutinio.

        Presuppone che l'orologio abbia gia' superato `t_chiusura`: e' il chiamante
        (scenario/test) a simulare lo scorrere del tempo, tipicamente con
        `election.clock.set(election.params.t_chiusura + 1)`.  L'orchestratore NON
        tocca l'orologio: uno scrutinio richiesto a seggi ancora aperti fallisce
        qui, esplicitamente, invece di "riuscire" spostando il tempo di nascosto."""
        if self.clock() < self.params.t_chiusura:
            raise RuntimeError(
                "close_and_tally richiede now >= t_chiusura: i seggi sono ancora "
                "aperti.  Avanzare prima l'orologio "
                "(es. election.clock.set(election.params.t_chiusura + 1))."
            )
        self.ae.close()
        self._sync_cosign()
        self.ae.activate_tally_key(self.custodian)
        return self.ae.tally()

    # -------------------------------------------------------------- verifiche
    def verify_universal(self) -> VerificationReport:
        return self.verifier.verify_universal(self.ae.view())

    def verify_individual(self, voter: Voter) -> bool:
        return voter.verify_individual_inclusion(self.ae.view())

    def view(self):
        return self.ae.view()
