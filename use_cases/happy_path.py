"""Esecuzione dimostrativa: elezione end-to-end con tutti gli attori onesti.

L'elezione termina con la verifica individuale e la verifica universale entrambe
positive.  Stampa anche un riepilogo dei tempi di elaborazione delle singole fasi.
"""

from __future__ import annotations

import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from src.election import Election, demo_parameters
from src.sim import SimClock


def run(n_voters: int = 100, n_opzioni: int = 4, window_size: int = 10, verbose: bool = True) -> bool:
    clock = SimClock(start=1_700_000_000.0)
    params = demo_parameters(id_elezione="unisa-cds-2026", n_opzioni=n_opzioni, now=clock())
    election = Election.setup(params=params, clock=clock, window_size=window_size)

    def log(*a):
        if verbose:
            print(*a)

    t_phase1: list[float] = []
    t_phase23: list[float] = []

    log("=" * 78)
    log(f"Elezione '{params.id_elezione}'  -  N={params.n_opzioni} liste  -  {n_voters} elettori")
    log(f"Finestra di voto: [{params.t_apertura:.0f}, {params.t_chiusura:.0f}]  (epoch)")
    log(f"Pubblicazione per finestre: ogni {window_size} schede accettate")
    log("=" * 78)

    # --------------------------------------------------- autenticazione e voto
    voters = []
    expected = [0] * params.n_opzioni
    for k in range(n_voters):
        sid = f"studente_{k:03d}"
        election.enroll(sid)
        v = election.new_voter(sid)

        t0 = time.perf_counter()
        election.authenticate(v)                       # SSO/MFA + prova di possesso + C_p
        t_phase1.append((time.perf_counter() - t0) * 1000)

        pref = (k % params.n_opzioni) + 1
        expected[pref - 1] += 1

        t0 = time.perf_counter()
        r = election.cast_vote(v, pref)                # costruzione M -> ricevuta R verificata
        t_phase23.append((time.perf_counter() - t0) * 1000)

        voters.append(v)
        log(f"  {sid}: C_p emesso, voto -> lista {pref}, ricevuta R con j={r.j}, "
            f"PR_v cancellato={v.ephemeral_private_key_wiped}")

    # ----------------------------------------------------- chiusura e scrutinio
    log("-" * 78)
    election.clock.set(params.t_chiusura + 1)   # i seggi chiudono: il tempo simulato avanza
    t0 = time.perf_counter()
    doc = election.close_and_tally()
    t_close = (time.perf_counter() - t0) * 1000
    log(f"Chiusura + scrutinio black-box: Record_chiusura con k_totale={doc.k_totale}")
    log(f"Risultato={list(doc.risultato)}  (conformi={doc.k_conformi}, invalide={doc.k_invalide})")
    log(f"Atteso:   {expected}")
    tally_ok = tuple(expected) == doc.risultato

    # Controllo amministrativo: le schede totali non possono superare i certificati
    # emessi dal SA.  Richiede i log dell'IdP: e' un riscontro d'Ateneo, non del
    # Verificatore Pubblico (che non ha accesso al registro del SA).
    cp_emessi = election.sa.issued_count()
    admin_ok = doc.k_totale <= cp_emessi
    log(f"Controllo amministrativo: schede totali ({doc.k_totale}) <= certificati emessi ({cp_emessi}): {admin_ok}")

    # ------------------------------------------------------- verifica universale
    log("-" * 78)
    t0 = time.perf_counter()
    report = election.verify_universal()
    t_ver2 = (time.perf_counter() - t0) * 1000
    log(report.render())

    # ------------------------------------------------------ verifica individuale
    log("-" * 78)
    ver1_all = True
    t_ver1: list[float] = []
    for v in voters:
        t0 = time.perf_counter()
        ok = election.verify_individual(v)
        t_ver1.append((time.perf_counter() - t0) * 1000)
        ver1_all &= ok
    log(f"Verifica individuale positiva per tutti i {len(voters)} elettori: {ver1_all}")

    # ------------------------------------------------------------------- tempi
    def avg(xs):
        return sum(xs) / len(xs) if xs else 0.0

    log("-" * 78)
    log("Tempi di elaborazione per passo (ms, senza latenza di rete):")
    log(f"  autenticazione + emissione C_p   media {avg(t_phase1):8.3f}   (n={len(t_phase1)})")
    log(f"  costruzione scheda + ricevuta    media {avg(t_phase23):8.3f}   (n={len(t_phase23)})")
    log(f"  verifica individuale             media {avg(t_ver1):8.3f}   (n={len(t_ver1)})")
    log(f"  verifica universale             {t_ver2:8.3f}          (1 esecuzione)")
    log(f"  chiusura + scrutinio            {t_close:8.3f}          (1 esecuzione)")

    success = tally_ok and admin_ok and report.ok and ver1_all
    log("=" * 78)
    log(f"HAPPY PATH: {'SUCCESSO' if success else 'FALLITO'}")
    log("=" * 78)
    return success


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
