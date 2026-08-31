"""Fixture condivise + helper per i test.

Ottimizzazione dei tempi: la generazione di chiavi RSA-2048 domina il costo dei
test.  Una fixture autouse sostituisce `src.crypto.generate_rsa_keypair` con un
distributore che attinge da un POOL di coppie pre-generate una sola volta per
sessione.  Le coppie sono chiavi RSA-2048 reali: firme, verifiche e cifrature
restano autentiche.  Se il pool si esaurisce si ricade sulla generazione reale.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src import crypto as _crypto
from src.election import Election, demo_parameters
from src.merkle import MerkleTree, verify_proof
from src.messages import VoteRecord
from src.sim import SimClock

_REAL_GENERATE = _crypto.generate_rsa_keypair
_POOL_SIZE = 120


@pytest.fixture(scope="session")
def _keypair_pool():
    return [_REAL_GENERATE() for _ in range(_POOL_SIZE)]


@pytest.fixture(autouse=True)
def fast_rsa_keys(monkeypatch, _keypair_pool):
    state = {"i": 0}

    def _from_pool():
        i = state["i"]
        state["i"] += 1
        return _keypair_pool[i] if i < len(_keypair_pool) else _REAL_GENERATE()

    monkeypatch.setattr("src.crypto.generate_rsa_keypair", _from_pool)
    yield


@pytest.fixture
def clock():
    return SimClock(start=1_700_000_000.0)


@pytest.fixture
def make_election(clock):
    """Factory: costruisce un'elezione con N=4 e finestra di comodo."""

    def _make(n_opzioni: int = 4, window_size: int = 0):
        params = demo_parameters(id_elezione="test-elezione", n_opzioni=n_opzioni, now=clock())
        return Election.setup(params=params, clock=clock, window_size=window_size)

    return _make


def run_full_election(election, preferences: list[int]):
    """Esegue l'elezione completa per una lista di preferenze; restituisce (voters, doc)."""
    voters = []
    for k, pref in enumerate(preferences):
        sid = f"stud_{k:03d}"
        election.enroll(sid)
        v = election.new_voter(sid)
        election.authenticate(v)
        election.cast_vote(v, pref)
        voters.append(v)
    election.clock.set(election.params.t_chiusura + 1)   # i seggi chiudono
    doc = election.close_and_tally()
    return voters, doc


# --------------------------------------------------------------------------- tamper
class TamperableView:
    """Vista pubblica dell'urna *mutabile*, per costruire i casi negativi (record
    alterato/rimosso/iniettato, firma contraffatta, Root senza co-firma SA,
    Doc_finale alterato, ...).  Espone l'interfaccia consumata da PublicVerifier /
    Voter su strutture che il test puo' mutare liberamente."""

    def __init__(self, chain, roots, final_document, ae_public_key, params):
        self._chain = list(chain)
        self._roots = list(roots)
        self._doc = final_document
        self._ae_pub = ae_public_key
        self._params = params

    def chain(self):
        return list(self._chain)

    def genesis(self):
        return self._chain[0]

    def published_roots(self):
        return list(self._roots)

    def final_cosigned_root(self):
        target = None
        for b in self._chain:
            if b.__class__.__name__ == "ClosureRecord":
                target = b.merkle_root_finale
        for r in reversed(self._roots):
            if target is None or r.root == target:
                return r
        raise RuntimeError("nessuna Root definitiva")

    def final_document(self):
        return self._doc

    def ae_public_key(self):
        return self._ae_pub

    def params(self):
        return self._params

    def merkle_proof_for(self, f_j: bytes):
        fps = [b.f_j for b in self._chain if isinstance(b, VoteRecord)]
        idx = fps.index(f_j)  # ValueError se assente
        tree = MerkleTree(fps)
        return tree.prove(idx), tree.root()

    def verify_membership(self, f_j, proof, root) -> bool:
        return verify_proof(f_j, proof, root)


def snapshot(election) -> TamperableView:
    """Cattura lo stato pubblico corrente di un'elezione in una TamperableView."""
    urn = election.ae.urn
    return TamperableView(urn.chain, urn.roots, urn.final_document,
                          election.ae.public_key, election.params)
