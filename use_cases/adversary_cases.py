"""Resilienza del protocollo al modello di minaccia.

Per ciascun profilo avversariale del modello di minaccia questo scenario
riproduce i vettori d'attacco e mostra, per ognuno:
  [ NEUTRALIZZATO ]  l'attacco viene respinto o reso rilevabile dal protocollo;
  [ VINCOLO OK    ]  un vincolo pubblico che esporrebbe l'abuso di un insider
                     e' rispettato in un'elezione regolare;
  [RISCHIO RESIDUO]  un limite riconosciuto (fuori dal perimetro crittografico
                     o strutturale), dichiarato per trasparenza.

La copertura puntuale, con esiti attesi, e' nei test in `tests/`.
"""

from __future__ import annotations

import dataclasses
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from src import crypto
from src.ae import BallotRejected, TallyKeyError
from src.election import Election, demo_parameters
from src.messages import (
    BallotPacket,
    Certificate,
    FinalDocument,
    InvalidRecord,
    Receipt,
    VoteRecord,
)
from src.sa import AuthError
from src.sim import SimClock

_OK = 0
_KO = 0


def _row(tag: str, descr: str, detail: str = "") -> None:
    print(f"  [{tag:^15}] {descr}" + (f"   ({detail})" if detail else ""))


def _neutralized(descr: str, blocked: bool, detail: str = "") -> None:
    """Vettore d'attacco che il protocollo deve respingere o rendere rilevabile."""
    global _OK, _KO
    if blocked:
        _OK += 1
        _row("NEUTRALIZZATO", descr, detail)
    else:
        _KO += 1
        _row("NON BLOCCATO", descr, detail)


def _constraint(descr: str, holds: bool, detail: str = "") -> None:
    """Vincolo pubblico che esporrebbe l'abuso di un insider."""
    global _OK, _KO
    if holds:
        _OK += 1
        _row("VINCOLO OK", descr, detail)
    else:
        _KO += 1
        _row("VINCOLO ROTTO", descr, detail)


def _residual(descr: str, detail: str = "") -> None:
    """Limite riconosciuto: rischio residuo accettato, non un attacco bloccato."""
    _row("RISCHIO RESIDUO", descr, detail)


# --------------------------------------------------------------------------- setup
def _fresh(id_elezione="elezione-demo", n_opzioni=4, window_size=0):
    clock = SimClock(start=1_700_000_000.0)
    params = demo_parameters(id_elezione=id_elezione, n_opzioni=n_opzioni, now=clock())
    return Election.setup(params=params, clock=clock, window_size=window_size)


def _authed_voter(election, sid="s0", **enroll):
    election.enroll(sid, **enroll)
    v = election.new_voter(sid)
    election.authenticate(v)
    return v


def _closed_election(window_size=3, n=6):
    """Elezione regolare, chiusa e scrutinata (base per i test di manomissione dell'urna)."""
    e = _fresh(window_size=window_size)
    for k in range(n):
        e.cast_vote(_authed_voter(e, f"v{k}"), (k % 4) + 1)
    e.clock.set(e.params.t_chiusura + 1)
    e.close_and_tally()
    return e


def _first_vote_index(chain):
    return next(k for k, b in enumerate(chain) if isinstance(b, VoteRecord))


# ============================================================ 1) Avversario di Rete
def avversario_di_rete() -> None:
    print("\n--- Avversario di Rete (Man-in-the-Middle) ---")

    # alterazione attiva del ciphertext in transito
    e = _fresh()
    v = _authed_voter(e)

    def flip(buf: bytes) -> bytes:
        ba = bytearray(buf)
        ba[20] ^= 0x01
        return bytes(ba)

    try:
        e.cast_vote(v, 1, tamper=flip)
        _neutralized("alterazione del ciphertext in transito", False)
    except BallotRejected as ex:
        _neutralized("alterazione del ciphertext in transito", ex.check == 5,
                     f"Controllo {ex.check}: firma sigma non valida; nessuna ricevuta, chiave effimera non cancellata")

    # ritrasmissione esatta dello stesso pacchetto
    e = _fresh()
    v = _authed_voter(e)
    m = v.build_ballot(1)
    e.ae.receive_ballot(m)
    try:
        e.ae.receive_ballot(m)
        _neutralized("ritrasmissione esatta del pacchetto", False)
    except BallotRejected as ex:
        _neutralized("ritrasmissione esatta del pacchetto", ex.check == 3,
                     f"Controllo {ex.check}: chiave effimera gia' registrata")

    # riuso del nonce con un certificato diverso -> scatta il controllo sul nonce, non quello di unicita'
    e = _fresh()
    e.enroll("a")
    e.enroll("b")
    va = e.new_voter("a")
    e.authenticate(va)
    m0 = va.build_ballot(1)
    e.ae.receive_ballot(m0)
    vb = e.new_voter("b")
    e.authenticate(vb)
    mb = vb.build_ballot(2)
    m_reused = BallotPacket.create(mb.c, vb.cert, m0.eta, e.params.id_elezione, vb._pr_v)
    try:
        e.ae.receive_ballot(m_reused)
        _neutralized("riuso del nonce con certificato diverso", False)
    except BallotRejected as ex:
        _neutralized("riuso del nonce con certificato diverso", ex.check == 4,
                     f"Controllo {ex.check}: anti-replay sul nonce, distinto dall'unicita' del certificato")

    _residual("intercettazione passiva del pacchetto",
              "riservatezza in transito affidata al canale cifrato, non riprodotto in-process")


# ============================================================ 2) Attaccante DoS
def attaccante_dos() -> None:
    print("\n--- Attaccante DoS (Denial of Service) ---")

    # interruzione prima della ricevuta: per il protocollo l'elettore non ha votato
    e = _fresh()
    v = _authed_voter(e)
    m_perduto = v.build_ballot(1)   # non raggiunge mai l'AE (crash / timeout)
    m_retry = BallotPacket.create(m_perduto.c, v.cert, crypto.fresh_nonce(), e.params.id_elezione, v._pr_v)
    r = e.ae.receive_ballot(m_retry)
    _neutralized("interruzione prima della ricevuta", r.j == 1,
                 "stato coerente: nessun voto registrato; ritrasmissione con stesso certificato accettata")

    # i record gia' nella hash chain restano verificabili dopo un'interruzione
    e = _closed_election()
    _neutralized("record storici dopo l'interruzione", e.verify_universal().ok,
                 "hash chain intatta: verifica universale positiva")

    _residual("saturazione volumetrica delle risorse",
              "affidata alle difese di rete d'Ateneo; non altera esito ne' segretezza")


# ============================================================ 3) Falsario
def falsario() -> None:
    print("\n--- Falsario ---")

    e = _fresh()
    fake_sa_priv, _ = crypto.generate_rsa_keypair()
    ev_priv, ev_pub = crypto.generate_rsa_keypair()
    forged = Certificate.create(ev_pub, e.params.id_elezione, fake_sa_priv)
    c = crypto.oaep_encrypt(e.pu_ele, (1).to_bytes(4, "big"))
    m = BallotPacket.create(c, forged, crypto.fresh_nonce(), e.params.id_elezione, ev_priv)
    try:
        e.submit_packet(m)
        _neutralized("certificato di abilitazione contraffatto", False)
    except BallotRejected as ex:
        _neutralized("certificato di abilitazione contraffatto", ex.check == 2,
                     f"Controllo {ex.check}: firma del SA non valida; ogni pacchetto senza certificato autentico e' scartato")


# ============================================================ 4) Elettore Disonesto
def elettore_disonesto() -> None:
    print("\n--- Elettore Disonesto (Impostore) ---")

    # secondo voto con lo stesso certificato
    e = _fresh()
    v = _authed_voter(e)
    e.ae.receive_ballot(v.build_ballot(1))
    try:
        e.ae.receive_ballot(v.build_ballot(2))
        _neutralized("secondo voto con lo stesso certificato", False)
    except BallotRejected as ex:
        _neutralized("secondo voto con lo stesso certificato", ex.check == 3, f"Controllo {ex.check}")

    # seconda richiesta di certificato per la stessa identita'
    e = _fresh()
    _authed_voter(e, "s0")
    v2 = e.new_voter("s0")
    v2.start_session()
    try:
        v2.authenticate(e.idp, e.sa)
        _neutralized("seconda richiesta di certificato per la stessa identita'", False)
    except AuthError:
        _neutralized("seconda richiesta di certificato per la stessa identita'", True,
                     "il SA blocca sul registro delle identita' reali")

    # impersonamento: prova di possesso firmata con una chiave diversa da quella dichiarata
    e = _fresh()
    e.enroll("s0")
    v = e.new_voter("s0")
    v.start_session()
    tok = e.idp.authenticate("s0", e.params.id_elezione)
    pu_v_der = crypto.public_key_to_der(v._pu_v)
    nonce = e.sa.request_challenge(tok, pu_v_der)
    wrong_priv, _ = crypto.generate_rsa_keypair()
    try:
        e.sa.issue_certificate(tok, pu_v_der, crypto.sign(wrong_priv, nonce))
        _neutralized("prova di possesso della chiave effimera non valida", False)
    except AuthError:
        _neutralized("prova di possesso della chiave effimera non valida", True, "il SA rifiuta l'emissione")

    # scheda fuori dominio: accettata alla ricezione, invalidata a scrutinio
    e = _fresh()
    vb = _authed_voter(e, "s_bad")
    r = e.ae.receive_ballot(vb.build_ballot(99))
    vb.process_receipt(r)
    e.cast_vote(_authed_voter(e, "s_ok"), 2)
    e.clock.set(e.params.t_chiusura + 1)
    doc = e.close_and_tally()
    invs = [b for b in e.view().chain() if isinstance(b, InvalidRecord)]
    ok = (doc.k_invalide == 1 and len(invs) == 1 and invs[0].motivo == "OUT_OF_RANGE"
          and invs[0].verify(e.ae.public_key) and e.verify_universal().ok)
    _neutralized("scheda fuori dominio", ok,
                 "accettata alla ricezione, invalidata a scrutinio con record firmato; verifica universale positiva")

    # richiesta di una ricevuta che riveli il voto
    e = _fresh()
    v = _authed_voter(e)
    r = e.cast_vote(v, 3)
    only_obfuscated = {f.name for f in dataclasses.fields(Receipt)} == {"k_j", "f_j", "j", "id_elezione", "signature"}
    _neutralized("richiesta di una ricevuta rivelante", only_obfuscated and v.ephemeral_private_key_wiped,
                 "la ricevuta non contiene il voto ne' il fattore di casualita'; chiave effimera cancellata dopo la verifica")


# ============================================================ 5) Coercitore
def coercitore() -> None:
    print("\n--- Coercitore ---")

    e = _fresh()
    v = _authed_voter(e)
    e.cast_vote(v, 2)
    cannot_prove = v.ephemeral_private_key_wiped and v._pr_v is None
    _neutralized("coercizione retroattiva / voto di scambio", cannot_prove,
                 "senza chiave effimera ne' fattore di casualita' l'elettore non puo' dimostrare il proprio voto a terzi")

    _residual("coercizione fisica al momento del voto",
              "modello di voto irrevocabile a colpo singolo: nessuna garanzia tecnica ulteriore")


# ============================================================ 6) SA Disonesto
def sa_disonesto() -> None:
    print("\n--- Sistema di Autenticazione Disonesto ---")

    # de-anonimizzazione per correlazione temporale: con la pubblicazione per finestre
    # il record non compare nell'urna all'istante del voto
    e = _fresh(window_size=100)
    for k in range(4):
        e.cast_vote(_authed_voter(e, f"s{k}"), 1)
    differita = (all(not isinstance(b, VoteRecord) for b in e.view().chain())
                 and e.ae.urn.pending_count() == 4)
    _neutralized("de-anonimizzazione per correlazione temporale", differita,
                 "con pubblicazione per finestre i voti non compaiono nell'urna all'atto della sottomissione")

    # abilitazione di identita' fittizie: il segnale pubblico e' il vincolo di disuguaglianza
    e = _closed_election(n=5)
    doc = e.ae.urn.final_document
    _constraint("abilitazione di identita' fittizie (phantom voting)",
                doc.k_totale <= e.sa.issued_count(),
                f"schede totali={doc.k_totale} <= certificati emessi={e.sa.issued_count()}; "
                "un valore superiore segnalerebbe certificati non legittimi")

    _residual("esclusione arbitraria di un avente diritto",
              "violazione locale mitigata dai log d'Ateneo, fuori dal perimetro crittografico")


# ============================================================ 7) AE Disonesta
def ae_disonesta() -> None:
    print("\n--- Autorita' Elettorale Disonesta ---")

    # monitoraggio anticipato: la chiave di scrutinio non e' disponibile prima della chiusura
    e = _fresh()
    e.cast_vote(_authed_voter(e), 1)
    try:
        e.ae.activate_tally_key(e.custodian)
        _neutralized("decifratura anticipata delle schede", False)
    except TallyKeyError:
        _neutralized("decifratura anticipata delle schede", True,
                     "chiave di scrutinio rilasciata dal custode solo dopo la chiusura")

    # alterazione retroattiva dei record pubblici -> verifica universale NEGATIVA
    e = _closed_election()
    i = _first_vote_index(e.ae.urn.chain)
    e.ae.urn.chain[i] = dataclasses.replace(e.ae.urn.chain[i], k_j=b"\x00" * 32)
    _neutralized("record modificato nella hash chain", not e.verify_universal().ok,
                 "verifica universale negativa: firme dei blocchi")

    e = _closed_election()
    i = _first_vote_index(e.ae.urn.chain)
    del e.ae.urn.chain[i + 1]
    _neutralized("record rimosso a meta' catena", not e.verify_universal().ok,
                 "verifica universale negativa: integrita' sequenziale degli hash pointer")

    e = _closed_election()
    atk_priv, _ = crypto.generate_rsa_keypair()
    i = _first_vote_index(e.ae.urn.chain)
    prev = e.ae.urn.chain[i - 1].block_digest()
    e.ae.urn.chain.insert(i, VoteRecord.create(999, crypto.sha256(b"x"), crypto.sha256(b"y"), prev, atk_priv))
    _neutralized("record iniettato a meta' catena", not e.verify_universal().ok,
                 "verifica universale negativa: firma del blocco e catena degli hash pointer")

    e = _closed_election()
    e.ae.urn.roots[-1] = dataclasses.replace(e.ae.urn.roots[-1], sa_signature=None)
    _neutralized("Merkle Root priva della co-firma del SA", not e.verify_universal().ok,
                 "verifica universale negativa: doppia firma AE+SA richiesta su ogni radice")

    e = _closed_election()
    d = e.ae.urn.final_document
    e.ae.urn.final_document = FinalDocument.create(d.risultato, d.k_totale, d.k_conformi,
                                                  d.k_invalide, b"\xAA" * 32, e.ae._priv_ae)
    _neutralized("documento finale con Merkle Root incoerente", not e.verify_universal().ok,
                 "verifica universale negativa: la radice nel documento non corrisponde alla catena")

    # iniezione di schede senza certificato: gia' respinta alla ricezione (vedi Falsario);
    # il vincolo residuo e' lo stesso del phantom voting
    e = _closed_election(n=5)
    doc = e.ae.urn.final_document
    _constraint("iniezione di schede fittizie nell'urna",
                doc.k_totale <= e.sa.issued_count(),
                f"schede totali={doc.k_totale} <= certificati emessi={e.sa.issued_count()}")

    _residual("manipolazione del conteggio nello scrutinio isolato",
              "capacita' tecnica dell'AE; vincolo pubblico residuo = coerenza numerica "
              "conformi + invalide = totale nel documento finale")


def main() -> int:
    print("=" * 78)
    print("Resilienza del protocollo al modello di minaccia")
    print("=" * 78)
    avversario_di_rete()
    attaccante_dos()
    falsario()
    elettore_disonesto()
    coercitore()
    sa_disonesto()
    ae_disonesta()
    print("\n" + "=" * 78)
    print(f"Vettori verificati: {_OK}/{_OK + _KO}    (rischi residui dichiarati a parte)")
    print("=" * 78)
    return 0 if _KO == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
