"""Happy path: tutti gli attori onesti.

L'elezione termina con la verifica individuale e la verifica universale entrambe
positive.
"""

from __future__ import annotations

import dataclasses

import pytest

from conftest import run_full_election
from src.messages import VoteRecord


def test_completeness_ver1_and_ver2_positive(make_election):
    election = make_election(n_opzioni=4, window_size=5)
    prefs = [(k % 4) + 1 for k in range(12)]
    voters, doc = run_full_election(election, prefs)

    expected = [prefs.count(i) for i in (1, 2, 3, 4)]
    assert list(doc.risultato) == expected
    assert doc.k_conformi == 12 and doc.k_invalide == 0 and doc.k_totale == 12

    report = election.verify_universal()
    assert report.ok, report.render()

    for v in voters:
        assert election.verify_individual(v) is True


def test_receipt_signature_verified_before_wipe(make_election):
    election = make_election()
    election.enroll("s0")
    v = election.new_voter("s0")
    election.authenticate(v)
    r = election.cast_vote(v, 1)

    assert r.verify(election.ae.public_key)
    assert v.ephemeral_private_key_wiped is True
    # il ciphertext C si conserva (serve alla verifica individuale)
    assert v.c is not None and v.eta is not None


def test_tampered_receipt_blocks_wipe(make_election):
    """Se la firma su R non e' valida, l'elettore NON cancella PR_v."""
    election = make_election()
    election.enroll("s0")
    v = election.new_voter("s0")
    election.authenticate(v)
    m = v.build_ballot(2)
    receipt = election.ae.receive_ballot(m)
    forged = dataclasses.replace(receipt, j=receipt.j + 99)  # firma non piu' coerente
    with pytest.raises(Exception):
        v.process_receipt(forged)
    assert v.ephemeral_private_key_wiped is False


def test_urn_never_stores_ciphertext(make_election):
    election = make_election()
    voters, _ = run_full_election(election, [1, 2, 3])
    ciphertexts = {v.c for v in voters}
    for block in election.view().chain():
        if isinstance(block, VoteRecord):
            assert block.k_j not in ciphertexts
            assert len(block.k_j) == 32 and len(block.f_j) == 32


def test_windowed_publication_defers_records(make_election):
    """L'indice j e' fissato all'accettazione; la pubblicazione del Record_j e'
    differita alla finestra."""
    election = make_election(window_size=100)  # finestra piu' larga del numero di voti
    receipts = []
    for k in range(4):
        election.enroll(f"s{k}")
        v = election.new_voter(f"s{k}")
        election.authenticate(v)
        receipts.append(election.cast_vote(v, 1))

    assert [r.j for r in receipts] == [1, 2, 3, 4]
    chain_before = election.view().chain()
    assert all(not isinstance(b, VoteRecord) for b in chain_before)
    assert election.ae.urn.pending_count() == 4

    election.flush_window()
    published = [b for b in election.view().chain() if isinstance(b, VoteRecord)]
    assert [b.j for b in published] == [1, 2, 3, 4]  


def test_cosigned_roots_have_both_signatures(make_election):
    election = make_election(window_size=3)
    run_full_election(election, [1, 2, 3, 4, 1, 2])
    view = election.view()
    pu_ae = view.ae_public_key()
    pu_sa = election.sa.public_key
    roots = view.published_roots()
    assert len(roots) >= 1
    for root in roots:
        assert root.verify_ae(pu_ae)
        assert root.verify_sa(pu_sa)
