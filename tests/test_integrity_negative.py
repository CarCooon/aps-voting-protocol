"""Test negativi sulle verifiche di integrita'.

La verifica universale e la verifica della hash chain devono restituire esito
NEGATIVO di fronte a: record modificato, record rimosso, record iniettato a
meta' catena, firma AE contraffatta, Merkle Root incoerente con il Doc_finale,
Doc_finale alterato, Root priva della co-firma del SA.  In coda anche negativi
sulla verifica individuale.
"""

from __future__ import annotations

import dataclasses

import pytest

from conftest import snapshot
from src import crypto
from src.messages import ClosureRecord, FinalDocument, InvalidRecord, VoteRecord


@pytest.fixture
def built(make_election):
    """Elezione completa e valida, 6 schede tutte conformi (nessun Invalid_j:
    cosi' l'ultimo blocco della catena e' il Record_chiusura)."""
    election = make_election(n_opzioni=4, window_size=3)
    voters = []
    for k in range(6):
        sid = f"stud_{k}"
        election.enroll(sid)
        v = election.new_voter(sid)
        election.authenticate(v)
        election.cast_vote(v, (k % 4) + 1)
        voters.append(v)
    election.clock.set(election.params.t_chiusura + 1)   
    election.close_and_tally()
    return election, voters


def _first_vote_index(chain):
    for i, b in enumerate(chain):
        if isinstance(b, VoteRecord):
            return i
    raise AssertionError("nessun VoteRecord")


# --------------------------------------------------------------- sanity (positivo)
def test_untampered_snapshot_verifies(built):
    election, _ = built
    view = snapshot(election)
    assert election.verifier.verify_universal(view).ok is True


# --------------------------------------------------------------- 1) record modificato
def test_modified_record_detected(built):
    election, _ = built
    view = snapshot(election)
    i = _first_vote_index(view._chain)
    view._chain[i] = dataclasses.replace(view._chain[i], k_j=b"\x00" * 32)

    report = election.verifier.verify_universal(view)
    assert report.ok is False
    assert report.checks["firme_AE_su_ogni_blocco"] is False


# --------------------------------------------------------------- 2) record rimosso
def test_removed_record_detected(built):
    election, _ = built
    view = snapshot(election)
    i = _first_vote_index(view._chain) + 1  
    assert isinstance(view._chain[i], VoteRecord)
    del view._chain[i]

    report = election.verifier.verify_universal(view)
    assert report.ok is False
    assert report.checks["integrita_sequenziale_hash_chain"] is False


# ------------------------------------------------------ 3) record iniettato a meta'
def test_injected_record_detected(built):
    election, _ = built
    view = snapshot(election)
    atk_priv, _ = crypto.generate_rsa_keypair()
    i = _first_vote_index(view._chain) + 1
    prev = view._chain[i - 1].block_digest()
    bogus = VoteRecord.create(999, crypto.sha256(b"x"), crypto.sha256(b"y"), prev, atk_priv)
    view._chain.insert(i, bogus)

    report = election.verifier.verify_universal(view)
    assert report.ok is False
    assert report.checks["firme_AE_su_ogni_blocco"] is False
    assert report.checks["integrita_sequenziale_hash_chain"] is False


# ---------------------------------------------------- 4) firma AE contraffatta
def test_forged_ae_signature_detected(built):
    election, _ = built
    view = snapshot(election)
    atk_priv, _ = crypto.generate_rsa_keypair()
    # ultimo blocco = Record_chiusura: nulla vi punta -> isola il controllo firme
    assert isinstance(view._chain[-1], ClosureRecord)
    closure = view._chain[-1]
    view._chain[-1] = dataclasses.replace(closure, signature=crypto.sign(atk_priv, closure.signed_bytes()))

    report = election.verifier.verify_universal(view)
    assert report.ok is False
    assert report.checks["firme_AE_su_ogni_blocco"] is False
    assert report.checks["integrita_sequenziale_hash_chain"] is True  # isolato


# ------------------------------- 5) Merkle Root incoerente con il Doc_finale
def test_merkle_root_inconsistent_with_final_document_detected(built):
    election, _ = built
    view = snapshot(election)
    real = view._doc
    view._doc = FinalDocument.create(
        real.risultato, real.k_totale, real.k_conformi, real.k_invalide,
        b"\xAA" * 32, election.ae._priv_ae,
    )
    report = election.verifier.verify_universal(view)
    assert report.ok is False
    assert report.checks["firma_doc_finale"] is True            
    assert report.checks["merkle_root_vs_doc_finale"] is False   


# --------------------------------------------------- 6) Doc_finale alterato
def test_altered_final_document_detected(built):
    election, _ = built
    view = snapshot(election)
    view._doc = dataclasses.replace(view._doc, k_conformi=view._doc.k_conformi + 1)
    report = election.verifier.verify_universal(view)
    assert report.ok is False
    assert report.checks["firma_doc_finale"] is False


# ------------------------------------------ 7) Root priva della co-firma del SA
def test_root_without_sa_cosignature_detected(built):
    election, _ = built
    view = snapshot(election)
    view._roots[-1] = dataclasses.replace(view._roots[-1], sa_signature=None)
    report = election.verifier.verify_universal(view)
    assert report.ok is False
    assert report.checks["cofirme_AE_SA_su_ogni_merkle_root"] is False


def test_root_with_forged_sa_cosignature_detected(built):
    election, _ = built
    view = snapshot(election)
    atk_priv, _ = crypto.generate_rsa_keypair()
    r = view._roots[-1]
    view._roots[-1] = dataclasses.replace(r, sa_signature=crypto.sign(atk_priv, r.signed_bytes()))
    report = election.verifier.verify_universal(view)
    assert report.ok is False
    assert report.checks["cofirme_AE_SA_su_ogni_merkle_root"] is False


# ------------------ Invalid_j non corrispondenti a Record_j (deflazione conteggio)
def test_duplicate_invalid_record_for_same_j_detected(built):
    """Un'AE che accoda DUE Invalid_j per lo stesso j sgonfia k_conformi tramite
    la derivazione k_totale - k_invalide: la guardia sui j duplicati lo rileva."""
    election, voters = built
    view = snapshot(election)
    vr = next(b for b in view._chain if isinstance(b, VoteRecord) and b.j == voters[0].j)
    prev = view._chain[-1].block_digest()
    dup = InvalidRecord.create(
        election.params.id_elezione, vr.j, vr.k_j, "OUT_OF_RANGE", prev, election.ae._priv_ae
    )
    view._chain.append(dup)
    dup2 = InvalidRecord.create(
        election.params.id_elezione, vr.j, vr.k_j, "OUT_OF_RANGE", dup.block_digest(), election.ae._priv_ae
    )
    view._chain.append(dup2)

    report = election.verifier.verify_universal(view)
    assert report.ok is False
    assert report.checks["invalid_j_corrispondono_a_record_j"] is False


def test_invalid_record_for_unknown_j_detected(built):
    """Un Invalid_j che si riferisce a un j senza Record_j corrispondente."""
    election, _ = built
    view = snapshot(election)
    prev = view._chain[-1].block_digest()
    bogus = InvalidRecord.create(
        election.params.id_elezione, 99999, crypto.sha256(b"z"), "DECRYPT_FAILED", prev, election.ae._priv_ae
    )
    view._chain.append(bogus)
    report = election.verifier.verify_universal(view)
    assert report.ok is False
    assert report.checks["invalid_j_corrispondono_a_record_j"] is False


# ------------------------------------------- negativi sulla verifica individuale
def test_ver1_detects_removed_own_record(built):
    election, voters = built
    v = voters[2]
    view = snapshot(election)
    view._chain[:] = [b for b in view._chain if not (isinstance(b, VoteRecord) and b.j == v.j)]
    assert v.verify_individual_inclusion(view) is False


def test_ver1_detects_tampered_final_root(built):
    election, voters = built
    v = voters[0]
    view = snapshot(election)
    view._roots[-1] = dataclasses.replace(view._roots[-1], root=b"\x00" * 32)
    assert v.verify_individual_inclusion(view) is False
