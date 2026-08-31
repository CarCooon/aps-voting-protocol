"""Resilienza al modello di minaccia.

Ogni test riproduce un vettore d'attacco e verifica che il protocollo lo
neutralizzi nel punto previsto.
"""

from __future__ import annotations

import pytest

from src import crypto
from src.ae import BallotRejected, TallyKeyError
from src.election import Election
from src.messages import BallotPacket, Certificate, ElectionParams, InvalidRecord
from src.sa import AuthError


# ------------------------------------------------ Controllo 1: finestra temporale
def test_ballot_after_closure_rejected_by_control_1(make_election):
    """Pacchetto dopo t_chiusura: Controllo 1 (confronto reale con l'orologio),
    non il flag di urna chiusa."""
    election = make_election()
    election.enroll("s0")
    v = election.new_voter("s0")
    election.authenticate(v)
    m = v.build_ballot(1)

    election.clock.set(election.params.t_chiusura + 1)  # oltre t_chiusura, urna ancora aperta
    with pytest.raises(BallotRejected) as ei:
        election.ae.receive_ballot(m)
    assert ei.value.check == 1
    assert "t_chiusura" in ei.value.reason


def test_ballot_before_opening_rejected_by_control_1(clock):
    """Pacchetto prima di t_apertura: Controllo 1.  Finestra spostata nel futuro;
    autenticazione e costruzione della scheda riescono comunque."""
    params = ElectionParams(
        id_elezione="pre-apertura", n_opzioni=3, lista_candidati=("A", "B", "C"),
        t_apertura=clock() + 100.0, t_chiusura=clock() + 3600.0,
    )
    election = Election.setup(params=params, clock=clock)
    election.enroll("s0")
    v = election.new_voter("s0")
    election.authenticate(v)               
    m = v.build_ballot(1)
    with pytest.raises(BallotRejected) as ei:
        election.ae.receive_ballot(m)
    assert ei.value.check == 1
    assert "t_apertura" in ei.value.reason


# --------------------------------------------------------------------------- MITM
def test_mitm_tampering_in_transit_rejected(make_election):
    """Avversario di rete attivo: altera C in transito -> sigma non valida.
    Nessuna ricevuta -> PR_v non cancellato."""
    election = make_election()
    election.enroll("s0")
    v = election.new_voter("s0")
    election.authenticate(v)

    def flip_byte(buf: bytes) -> bytes:
        ba = bytearray(buf)
        ba[20] ^= 0x01
        return bytes(ba)

    with pytest.raises(BallotRejected) as ei:
        election.cast_vote(v, 1, tamper=flip_byte)
    assert ei.value.check == 5
    assert v.ephemeral_private_key_wiped is False


def test_exact_replay_blocked_by_uniqueness(make_election):
    """Replay esatto dello stesso M: bloccato gia' dal Controllo 3 (PU_v gia'
    registrata)."""
    election = make_election()
    election.enroll("s0")
    v = election.new_voter("s0")
    election.authenticate(v)
    m = v.build_ballot(1)
    r = election.ae.receive_ballot(m)
    v.process_receipt(r)

    with pytest.raises(BallotRejected) as ei:
        election.ae.receive_ballot(m)
    assert ei.value.check == 3


def test_nonce_antireplay_distinct_from_uniqueness(make_election):
    """Stesso eta ma C_p / PU_v DIVERSI: deve scattare il Controllo 4 (anti-replay
    sul nonce), non il Controllo 3 (unicita' di PU_v).  Esercita il caso limite in
    cui i due controlli non coincidono."""
    election = make_election()
    election.enroll("s0")
    election.enroll("s1")

    v0 = election.new_voter("s0")
    election.authenticate(v0)
    m0 = v0.build_ballot(1)
    election.ae.receive_ballot(m0)          
    eta_reused = m0.eta

    v1 = election.new_voter("s1")
    election.authenticate(v1)               # identita' diversa -> C_p / PU_v diversi
    m1_base = v1.build_ballot(2)
    m1 = BallotPacket.create(m1_base.c, v1.cert, eta_reused, election.params.id_elezione, v1._pr_v)

    with pytest.raises(BallotRejected) as ei:
        election.ae.receive_ballot(m1)
    assert ei.value.check == 4


def test_retransmission_after_interruption_allowed(make_election):
    """Interruzione prima della ricevuta (DoS / crash): la ritrasmissione con lo
    stesso C_p e un nuovo eta e' accettata."""
    election = make_election()
    election.enroll("s0")
    v = election.new_voter("s0")
    election.authenticate(v)
    m = v.build_ballot(1)  

    m_retry = BallotPacket.create(m.c, v.cert, crypto.fresh_nonce(), election.params.id_elezione, v._pr_v)
    r = election.ae.receive_ballot(m_retry)
    assert r.j == 1


# ------------------------------------------------------------------ doppio voto
def test_double_vote_same_certificate_blocked(make_election):
    """Elettore disonesto: due schede con lo stesso C_p -> Controllo 3."""
    election = make_election()
    election.enroll("s0")
    v = election.new_voter("s0")
    election.authenticate(v)
    m1 = v.build_ballot(1)
    election.ae.receive_ballot(m1)

    m2 = v.build_ballot(2)  
    with pytest.raises(BallotRejected) as ei:
        election.ae.receive_ballot(m2)
    assert ei.value.check == 3


def test_double_certificate_request_blocked_by_sa(make_election):
    """Elettore disonesto: seconda richiesta di C_p per la stessa identita' ->
    bloccata dal SA (registro interno per identita' reale)."""
    election = make_election()
    election.enroll("s0")
    v1 = election.new_voter("s0")
    election.authenticate(v1)

    v2 = election.new_voter("s0")
    v2.start_session()
    with pytest.raises(AuthError):
        v2.authenticate(election.idp, election.sa)


# --------------------------------------------------------------------- Falsario
def test_forged_certificate_rejected(make_election):
    """Falsario: C_p firmato con una chiave diversa da PR_SA -> Controllo 2."""
    election = make_election()
    fake_sa_priv, _ = crypto.generate_rsa_keypair()
    ev_priv, ev_pub = crypto.generate_rsa_keypair()
    forged = Certificate.create(ev_pub, election.params.id_elezione, fake_sa_priv)

    c = crypto.oaep_encrypt(election.pu_ele, (1).to_bytes(4, "big"))
    m = BallotPacket.create(c, forged, crypto.fresh_nonce(), election.params.id_elezione, ev_priv)

    with pytest.raises(BallotRejected) as ei:
        election.submit_packet(m)
    assert ei.value.check == 2


def test_invalid_proof_of_possession_rejected(make_election):
    """Falsario / elettore disonesto: firma la challenge con una chiave diversa
    da PU_v dichiarata -> il SA rifiuta la prova di possesso."""
    election = make_election()
    election.enroll("s0")
    v = election.new_voter("s0")
    v.start_session()
    id_token = election.idp.authenticate("s0", election.params.id_elezione)
    pu_v_der = crypto.public_key_to_der(v._pu_v)
    nonce = election.sa.request_challenge(id_token, pu_v_der)

    wrong_priv, _ = crypto.generate_rsa_keypair()
    bad_pop = crypto.sign(wrong_priv, nonce)
    with pytest.raises(AuthError):
        election.sa.issue_certificate(id_token, pu_v_der, bad_pop)


# -------------------------------------------------------------------- id_elezione
def test_ballot_for_other_election_rejected(make_election):
    """M.id_elezione diverso dall'elezione corrente -> Controllo 2."""
    election = make_election()
    election.enroll("s0")
    v = election.new_voter("s0")
    election.authenticate(v)
    c = crypto.oaep_encrypt(election.pu_ele, (1).to_bytes(4, "big"))
    m = BallotPacket.create(c, v.cert, crypto.fresh_nonce(), "elezione-diversa", v._pr_v)
    with pytest.raises(BallotRejected) as ei:
        election.submit_packet(m)
    assert ei.value.check == 2


def test_certificate_for_other_election_rejected(make_election):
    """C_p.id_elezione diverso dall'elezione corrente -> Controllo 2
    (anti-replay cross-elezione)."""
    election = make_election()
    election.enroll("s0")
    v = election.new_voter("s0")
    election.authenticate(v)
    foreign_cert = Certificate.create(v._pu_v, "elezione-2025", election.sa._priv)
    c = crypto.oaep_encrypt(election.pu_ele, (1).to_bytes(4, "big"))
    m = BallotPacket.create(c, foreign_cert, crypto.fresh_nonce(), election.params.id_elezione, v._pr_v)
    with pytest.raises(BallotRejected) as ei:
        election.submit_packet(m)
    assert ei.value.check == 2


def test_ineligible_voter_refused_by_sa(make_election):
    """Non avente diritto: il SA non emette C_p."""
    election = make_election()
    election.enroll("s0", eligible=False)
    v = election.new_voter("s0")
    v.start_session()
    with pytest.raises(AuthError):
        v.authenticate(election.idp, election.sa)


def test_mfa_required(make_election):
    """Senza MFA l'IdP non autentica."""
    election = make_election()
    election.enroll("s0", has_mfa=False)
    v = election.new_voter("s0")
    v.start_session()
    with pytest.raises(Exception):
        v.authenticate(election.idp, election.sa)


# --------------------------------------------------- scheda malformata a scrutinio
def test_out_of_range_ballot_accepted_then_invalidated(make_election):
    """Elettore disonesto: scheda fuori dominio.  Accettata alla ricezione (supera
    i 5 controlli), scartata a scrutinio con Invalid_j firmato e accodato."""
    election = make_election(n_opzioni=4)
    election.enroll("s_bad")
    vb = election.new_voter("s_bad")
    election.authenticate(vb)
    m = vb.build_ballot(99)  
    r = election.ae.receive_ballot(m)   
    vb.process_receipt(r)

    election.enroll("s_ok")
    vo = election.new_voter("s_ok")
    election.authenticate(vo)
    election.cast_vote(vo, 2)

    election.clock.set(election.params.t_chiusura + 1)   
    doc = election.close_and_tally()
    assert doc.k_invalide == 1
    assert doc.k_conformi == 1
    assert list(doc.risultato) == [0, 1, 0, 0]

    invs = [b for b in election.view().chain() if isinstance(b, InvalidRecord)]
    assert len(invs) == 1
    assert invs[0].motivo == "OUT_OF_RANGE"
    assert invs[0].j == r.j and invs[0].k_j == r.k_j
    assert invs[0].verify(election.ae.public_key)          # firmato dall'AE
    assert election.verify_universal().ok                  # la verifica universale resta positiva


def test_undecryptable_ballot_invalidated(make_election):
    """Scheda cifrata con una chiave diversa da PU_ele: passa i 5 controlli
    (sigma valida su quel C), fallisce solo a scrutinio -> Invalid_j DECRYPT_FAILED."""
    election = make_election(n_opzioni=4)
    election.enroll("s0")
    v = election.new_voter("s0")
    election.authenticate(v)

    _, wrong_pub = crypto.generate_rsa_keypair()
    c = crypto.oaep_encrypt(wrong_pub, (1).to_bytes(4, "big"))
    m = BallotPacket.create(c, v.cert, crypto.fresh_nonce(), election.params.id_elezione, v._pr_v)
    r = election.ae.receive_ballot(m)   # supera i 5 controlli (sigma valida su questo C)
    assert r.j == 1

    election.clock.set(election.params.t_chiusura + 1)   
    doc = election.close_and_tally()
    assert doc.k_invalide == 1 and doc.k_conformi == 0
    invs = [b for b in election.view().chain() if isinstance(b, InvalidRecord)]
    assert invs[0].motivo == "DECRYPT_FAILED"
    assert election.verify_universal().ok


def test_malformed_plaintext_length_invalidated(make_election):
    """Plaintext decifrabile ma di lunghezza != 4 byte (codifica del voto non
    conforme) -> Invalid_j MALFORMED_PADDING."""
    election = make_election(n_opzioni=4)
    election.enroll("s0")
    v = election.new_voter("s0")
    election.authenticate(v)

    c = crypto.oaep_encrypt(election.pu_ele, b"\x00\x00")  
    m = BallotPacket.create(c, v.cert, crypto.fresh_nonce(), election.params.id_elezione, v._pr_v)
    election.ae.receive_ballot(m)

    election.clock.set(election.params.t_chiusura + 1)   
    doc = election.close_and_tally()
    assert doc.k_invalide == 1 and doc.k_conformi == 0
    invs = [b for b in election.view().chain() if isinstance(b, InvalidRecord)]
    assert invs[0].motivo == "MALFORMED_PADDING"
    assert election.verify_universal().ok


def test_pr_ele_not_available_before_closure(make_election):
    """PR_ele non attivabile prima di t_chiusura / a urna aperta (difesa contro il
    monitoraggio anticipato)."""
    election = make_election()
    election.enroll("s0")
    v = election.new_voter("s0")
    election.authenticate(v)
    election.cast_vote(v, 1)

    with pytest.raises(TallyKeyError):
        election.ae.activate_tally_key(election.custodian)
    with pytest.raises(TallyKeyError):
        election.custodian.release()
