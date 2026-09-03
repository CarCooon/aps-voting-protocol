"""Misura delle prestazioni del protocollo.

Tre scenari isolati; ogni funzione `bench_*` misura in liste locali e restituisce
le proprie righe, `main()` le scrive in CSV separati sotto artifacts/.

  1. bench_primitives  -> primitive_tempi.csv
     costo delle singole primitive: keygen RSA-2048, RSA-OAEP cifra/decifra, firma
     e verifica RSA-PSS, SHA-256, costruzione e prova del Merkle Tree, verifica
     della hash chain.
  2. bench_end_to_end  -> e2e_tempi.csv, e2e_dimensioni.csv
     un'elezione completa con attori onesti: tempo di elaborazione per passo,
     dimensione dei messaggi scambiati, latenza delle due verifiche.
  3. bench_scale       -> scala.csv
     come scalano la prova di inclusione (O(log n)) e la verifica universale
     (O(n)) al crescere del numero di schede, fino alla scala di un ateneo.
     Gira su un'"urna sintetica": vedi la docstring di `_synthetic_urn`.

Metodologia
  - Tempi = sola elaborazione per passo: il trasporto e' in-process, non c'e'
    latenza di rete.
  - Dimensioni = serializzazione binaria canonica lunghezza-prefissata (la stessa
    con cui si calcolano i byte da firmare): DER per le chiavi, byte grezzi per
    digest/ciphertext/firme, +5 byte di framing per campo.  Non hex, non JSON.
"""

from __future__ import annotations

import csv
import pathlib
import platform
import random
import statistics
import sys
import time

import cryptography

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from src import crypto
from src.election import Election, demo_parameters
from src.merkle import MerkleTree, verify_proof
from src.messages import (
    ClosureRecord,
    CoSignedRoot,
    FinalDocument,
    GenesisRecord,
    VoteRecord,
)
from src.sim import SimClock
from src.verifier import PublicVerifier

ARTIFACTS = pathlib.Path(__file__).resolve().parents[1] / "artifacts"
ID_ELEZIONE = "unisa-bench"  # id dello scenario end-to-end: le dimensioni dei messaggi valgono per un id di questa lunghezza


# --------------------------------------------------------------------------- util
def _stats(samples: list[float]) -> dict:
    n = len(samples)
    return {
        "n": n,
        "media": statistics.fmean(samples) if n else 0.0,
        "dev_std": statistics.pstdev(samples) if n > 1 else 0.0,
        "min": min(samples) if n else 0.0,
        "max": max(samples) if n else 0.0,
    }


def _time(fn, reps: int) -> list[float]:
    """Esegue `fn` `reps` volte, restituisce le durate in ms (lista locale)."""
    out = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t0) * 1000.0)
    return out


def _row(label: str, samples: list[float]) -> list[str]:
    s = _stats(samples)
    return [label, f"{s['n']:d}", f"{s['media']:.6f}", f"{s['dev_std']:.6f}",
            f"{s['min']:.6f}", f"{s['max']:.6f}"]


def _aligned(rows: list[list[str]], indent: str = "") -> list[str]:
    """Le righe di una tabella incolonnate su larghezza fissa per colonna."""
    widths = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    return [indent + "  ".join(str(c).ljust(w) for c, w in zip(r, widths)) for r in rows]


_TIME_HEADER = ["operazione", "ripetizioni", "media_ms", "dev_std_ms", "min_ms", "max_ms"]


# ===================================================================== 1) primitive
def bench_primitives() -> list[list[str]]:
    reps = 200
    keygen_reps = 25
    merkle_n = 4096
    chain_n = 2000
    rows = [_TIME_HEADER]

    # --- generazione chiavi RSA-2048 ---
    t = []
    for _ in range(keygen_reps):
        t0 = time.perf_counter()
        priv, pub = crypto.generate_rsa_keypair()
        t.append((time.perf_counter() - t0) * 1000)
    rows.append(_row("keygen RSA-2048", t))

    # --- RSA-OAEP encrypt / decrypt (plaintext 4 byte = codifica del voto i) ---
    pt = (3).to_bytes(4, "big")
    cts, t_enc = [], []
    for _ in range(reps):
        t0 = time.perf_counter()
        c = crypto.oaep_encrypt(pub, pt)
        t_enc.append((time.perf_counter() - t0) * 1000)
        cts.append(c)
    rows.append(_row("RSA-OAEP encrypt (voto 4 B)", t_enc))
    t_dec = []
    for c in cts:
        t0 = time.perf_counter()
        crypto.oaep_decrypt(priv, c)
        t_dec.append((time.perf_counter() - t0) * 1000)
    rows.append(_row("RSA-OAEP decrypt", t_dec))

    # --- firma / verifica hash-and-sign (RSA-PSS) su ~256 B ---
    msg = crypto.csprng_bytes(256)
    sigs, t_sig = [], []
    for _ in range(reps):
        t0 = time.perf_counter()
        s = crypto.sign(priv, msg)
        t_sig.append((time.perf_counter() - t0) * 1000)
        sigs.append(s)
    rows.append(_row("firma hash-and-sign RSA-PSS (256 B)", t_sig))
    t_ver = []
    for s in sigs:
        t0 = time.perf_counter()
        crypto.verify(pub, msg, s)
        t_ver.append((time.perf_counter() - t0) * 1000)
    rows.append(_row("verifica firma hash-and-sign RSA-PSS", t_ver))

    # --- SHA-256 su 256 B ---
    rows.append(_row("SHA-256 (256 B)", _time(lambda: crypto.sha256(msg), reps * 20)))

    # --- Merkle: build, proof gen, proof verify ---
    leaves = [crypto.csprng_bytes(32) for _ in range(merkle_n)]
    t_build = []
    for _ in range(20):
        t0 = time.perf_counter()
        tree = MerkleTree(leaves)
        t_build.append((time.perf_counter() - t0) * 1000)
    rows.append(_row(f"costruzione Merkle Tree (n={merkle_n})", t_build))
    root = tree.root()
    idxs = [random.randrange(merkle_n) for _ in range(reps)]
    proofs, t_gen = [], []
    for i in idxs:
        t0 = time.perf_counter()
        p = tree.prove(i)
        t_gen.append((time.perf_counter() - t0) * 1000)
        proofs.append((i, p))
    rows.append(_row(f"generazione Merkle proof (n={merkle_n})", t_gen))
    t_pv = []
    for i, p in proofs:
        t0 = time.perf_counter()
        verify_proof(leaves[i], p, root)
        t_pv.append((time.perf_counter() - t0) * 1000)
    rows.append(_row(f"verifica Merkle proof (n={merkle_n})", t_pv))

    # --- verifica hash chain (O(n)) ---
    chain: list[VoteRecord] = []
    prev = crypto.sha256(b"genesi-sintetica")
    for j in range(1, chain_n + 1):
        k_j = crypto.sha256(j.to_bytes(4, "big"))
        f_j = crypto.sha256(k_j + crypto.csprng_bytes(32))
        rec = VoteRecord.create(j, k_j, f_j, prev, priv)
        chain.append(rec)
        prev = rec.block_digest()

    def _verify_chain():
        p = crypto.sha256(b"genesi-sintetica")
        for rec in chain:
            if rec.prev_hash != p or not rec.verify(pub):
                raise AssertionError
            p = rec.block_digest()

    rows.append(_row(f"verifica hash chain (n={chain_n})", _time(_verify_chain, 10)))
    return rows


# ================================================================= 2) end-to-end
def bench_end_to_end() -> tuple[list[list[str]], list[list[str]]]:
    n_voters = 60
    n_opzioni = 4
    window_size = 10

    clock = SimClock(start=1_700_000_000.0)
    params = demo_parameters(id_elezione=ID_ELEZIONE, n_opzioni=n_opzioni, now=clock())
    election = Election.setup(params=params, clock=clock, window_size=window_size)

    t_ph1: list[float] = []
    t_ph2: list[float] = []
    t_ph3: list[float] = []
    size_m: list[int] = []
    size_r: list[int] = []
    voters = []

    for k in range(n_voters):
        sid = f"e2e_{k:04d}"
        election.enroll(sid)
        v = election.new_voter(sid)

        t0 = time.perf_counter()
        election.authenticate(v)
        t_ph1.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        m = v.build_ballot((k % n_opzioni) + 1)
        t_ph2.append((time.perf_counter() - t0) * 1000)
        on_wire = m.wire_bytes()
        size_m.append(len(on_wire))

        t0 = time.perf_counter()
        receipt = election.ae.receive_ballot(on_wire)   # l'AE riceve i byte e li deserializza
        t_ph3.append((time.perf_counter() - t0) * 1000)
        size_r.append(len(receipt.wire_bytes()))
        v.process_receipt(receipt)
        voters.append(v)

    election.flush_window()
    election.clock.set(params.t_chiusura + 1)   # i seggi chiudono: il tempo simulato avanza
    election.close_and_tally()

    t0 = time.perf_counter()
    report = election.verify_universal()
    t_ver2 = (time.perf_counter() - t0) * 1000
    assert report.ok, report.render()

    t_ver1: list[float] = []
    for v in voters:
        t0 = time.perf_counter()
        ok = election.verify_individual(v)
        t_ver1.append((time.perf_counter() - t0) * 1000)
        assert ok

    view = election.view()
    genesis_size = len(_genesis_wire(view.genesis()))
    record_j = next(b for b in view.chain() if isinstance(b, VoteRecord))
    closure = next(b for b in view.chain() if isinstance(b, ClosureRecord))

    times = [_TIME_HEADER,
             _row("autenticazione + emissione C_p", t_ph1),
             _row("costruzione della scheda M", t_ph2),
             _row("ricezione + ricevuta R", t_ph3),
             _row("latenza della verifica individuale (lato elettore)", t_ver1),
             _row("latenza della verifica universale", [t_ver2])]

    sizes = [["messaggio", "byte", "note"],
             ["M (pacchetto di voto, elettore -> AE)", str(round(statistics.fmean(size_m))),
              f"media su {n_voters}; id_elezione='{ID_ELEZIONE}'"],
             ["R (ricevuta firmata, AE -> elettore)", str(round(statistics.fmean(size_r))), ""],
             ["Record_0 / Params (blocco genesi)", str(genesis_size), ""],
             ["Record_j (blocco urna)", str(len(_record_wire(record_j))), ""],
             ["Record_chiusura", str(len(_record_wire(closure))), ""],
             ["Merkle proof (n=" + str(len(voters)) + ")", str(_proof_bytes(view, voters[0])),
              "32 B per hash fratello; cresce come ceil(log2 n)"]]
    return times, sizes


def _genesis_wire(g: GenesisRecord) -> bytes:
    return crypto.wire([g.signed_bytes(), g.signature])


def _record_wire(b) -> bytes:
    return crypto.wire([b.signed_bytes(), b.signature])


def _proof_bytes(view, voter) -> int:
    f = crypto.sha256(crypto.sha256(voter.c) + voter.eta)
    proof, _ = view.merkle_proof_for(f)
    return 32 * len(proof)


# ===================================================================== 3) scala
def _synthetic_urn(n: int, ae_priv, ae_pub, sa_priv, ele_pub, params):
    """Costruisce direttamente un'urna di `n` schede, senza rieseguire il
    protocollo completo `n` volte, per misurare il costo della verifica pubblica.

    Cosa e' reale e cosa e' sintetico:
      - reali: le firme dell'AE su ogni blocco, gli hash pointer che incatenano i
        blocchi, il Merkle Tree sui fingerprint, la co-firma AE+SA della Root, il
        Record_chiusura e il Doc_finale.  Su questa urna gira il verificatore
        universale *vero* (`PublicVerifier.verify_universal`), che infatti supera
        tutti i controlli;
      - sintetici: K_j e F_j sono byte casuali invece di H(C_j) e H(K_j || eta_j).
        Il verificatore pubblico non ricalcola mai questi valori a partire da C_j
        (che non e' pubblicato): ricostruisce solo la Merkle Root dai F_j.  Il
        costo di verifica dipende quindi dal numero e dalla struttura dei record,
        non da come sono stati prodotti.

    Non modellata: la pubblicazione per finestre.  Qui si pubblica una sola Root
    co-firmata; un'elezione reale con finestra W ne pubblica ceil(n/W) e il
    verificatore controlla 2 firme per ognuna.  E' un termine che dipende dalla
    configurazione del servizio, non da n, e resta fuori dalla curva O(n).

    Rieseguire il protocollo intero per n=50000 (n generazioni di chiavi RSA
    effimere, autenticazione, cinque controlli, ...) richiederebbe decine di
    minuti senza cambiare cio' che questo scenario misura.
    """
    rnd = random.Random(1234 + n)
    chain = [GenesisRecord.create(params, ele_pub, ae_priv)]
    prev = chain[0].block_digest()
    fps = []
    for j in range(1, n + 1):
        k_j = crypto.sha256(j.to_bytes(4, "big") + rnd.randbytes(8))
        f_j = crypto.sha256(k_j + rnd.randbytes(32))
        fps.append(f_j)
        rec = VoteRecord.create(j, k_j, f_j, prev, ae_priv)
        chain.append(rec)
        prev = rec.block_digest()

    tree = MerkleTree(fps)
    final_root = tree.root()
    root = CoSignedRoot.create_ae(0, final_root, n, ae_priv).with_sa_signature(sa_priv)
    chain.append(ClosureRecord.create(n, final_root, prev, ae_priv))

    risultato = [0] * params.n_opzioni
    for i in range(n):
        risultato[i % params.n_opzioni] += 1
    doc = FinalDocument.create(tuple(risultato), n, n, 0, final_root, ae_priv)

    class _View:
        def chain(self_):
            return list(chain)

        def genesis(self_):
            return chain[0]

        def published_roots(self_):
            return [root]

        def final_cosigned_root(self_):
            return root

        def final_document(self_):
            return doc

        def ae_public_key(self_):
            return ae_pub

        def params(self_):
            return params

    return _View(), fps, tree


def bench_scale() -> list[list[str]]:
    # Scala di un ateneo: l'Universita' di Salerno conta in media ~30-40 mila
    # iscritti, quindi la fascia 30k-40k e' l'operativita' reale; 50k e' margine.
    sizes = (500, 2_000, 5_000, 10_000, 20_000, 30_000, 35_000, 40_000, 50_000)
    ae_priv, ae_pub = crypto.generate_rsa_keypair()
    sa_priv, sa_pub = crypto.generate_rsa_keypair()
    _, ele_pub = crypto.generate_rsa_keypair()   # chiave di scrutinio nel blocco genesi, distinta da PU_AE
    params = demo_parameters(id_elezione="unisa-scala", n_opzioni=4)
    verifier = PublicVerifier(params, sa_pub)

    print("      urna sintetica per ogni n: genesi + n Record_j + 1 Merkle Root co-firmata")
    print("      AE+SA + Record_chiusura + Doc_finale; verifica con il verificatore reale")
    print(f"      valori di n: {', '.join(str(s) for s in sizes)}")

    rows = [["n_schede", "merkle_build_ms", "merkle_proof_n_hash", "merkle_proof_byte",
             "proof_gen_ms", "proof_verify_ms", "hash_chain_verify_ms", "verifica_universale_ms"]]

    for n in sizes:
        view, fps, tree = _synthetic_urn(n, ae_priv, ae_pub, sa_priv, ele_pub, params)
        root = tree.root()

        build = _time(lambda: MerkleTree(fps), 4)

        rnd = random.Random(99 + n)
        sample = [rnd.randrange(n) for _ in range(64)]
        proof_len = 0  # numero massimo di hash-fratello sul campione (limite O(log n))
        gen, ver = [], []
        for i in sample:
            t0 = time.perf_counter()
            p = tree.prove(i)
            gen.append((time.perf_counter() - t0) * 1000)
            proof_len = max(proof_len, len(p))
            t0 = time.perf_counter()
            verify_proof(fps[i], p, root)
            ver.append((time.perf_counter() - t0) * 1000)

        chain = view.chain()

        def _vc():
            p = chain[0].block_digest()
            for b in chain[1:]:
                if b.prev_hash != p or not b.verify(ae_pub):
                    raise AssertionError
                p = b.block_digest()

        # meno ripetizioni quando n e' grande: il costo per giro cresce con n e
        # poche misure bastano a stabilizzare la media
        hc_reps = 5 if n <= 5_000 else 3 if n <= 20_000 else 2
        v2_reps = 3 if n <= 5_000 else 2 if n <= 20_000 else 1

        hc = _time(_vc, hc_reps)
        v2, ok = [], True
        for _ in range(v2_reps):
            t0 = time.perf_counter()
            report = verifier.verify_universal(view)
            v2.append((time.perf_counter() - t0) * 1000)
            ok &= report.ok
        assert ok, "l'urna sintetica non supera la verifica universale"

        b_ms, hc_ms, v2_ms = _stats(build)["media"], _stats(hc)["media"], _stats(v2)["media"]
        print(f"      n={n:<6}  build {b_ms:7.1f} ms | prova {proof_len:2d} hash "
              f"| hash chain {hc_ms:8.1f} ms | verifica universale {v2_ms:8.1f} ms")

        rows.append([str(n), f"{b_ms:.4f}", str(proof_len), str(32 * proof_len),
                     f"{_stats(gen)['media']:.6f}", f"{_stats(ver)['media']:.6f}",
                     f"{hc_ms:.4f}", f"{v2_ms:.4f}"])
    return rows


# --------------------------------------------------------------------------- main
def _write_csv(path: pathlib.Path, rows: list[list[str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerows(rows)


def main() -> int:
    ARTIFACTS.mkdir(exist_ok=True)

    print("=" * 78)
    print("MISURA DELLE PRESTAZIONI DEL PROTOCOLLO DI VOTO")
    print("=" * 78)
    print(f"Piattaforma . . {platform.platform()}")
    print(f"Python  . . . . {platform.python_version()}  (pyca/cryptography {cryptography.__version__})")
    print(f"Primitive . . . RSA {crypto.RSA_KEY_SIZE} bit (e={crypto.RSA_PUBLIC_EXPONENT}), SHA-256, "
          "firma RSA-PSS (MGF1-SHA256, salt di lunghezza massima)")
    print("Tempi . . . . . sola elaborazione per passo; trasporto in-process, senza latenza di rete")
    print("Dimensioni  . . serializzazione binaria canonica lunghezza-prefissata (non hex/JSON)")
    print("=" * 78)

    print("\n[1/3] Costo delle singole primitive crittografiche")
    print("      keygen, RSA-OAEP cifra/decifra, firma e verifica RSA-PSS, SHA-256,")
    print("      costruzione e prova del Merkle Tree, verifica della hash chain.")
    prim = bench_primitives()
    _write_csv(ARTIFACTS / "primitive_tempi.csv", prim)
    print("\n".join(_aligned(prim, "      ")))

    print("\n[2/3] Elezione end-to-end con attori onesti")
    print("      tempo di elaborazione per passo, dimensione dei messaggi scambiati,")
    print("      latenza della verifica individuale e di quella universale.")
    e2e_times, e2e_sizes = bench_end_to_end()
    _write_csv(ARTIFACTS / "e2e_tempi.csv", e2e_times)
    _write_csv(ARTIFACTS / "e2e_dimensioni.csv", e2e_sizes)
    print("\n".join(_aligned(e2e_times, "      ")))
    print()
    print("\n".join(_aligned(e2e_sizes, "      ")))

    print("\n[3/3] Scala di un ateneo: O(log n) della prova di inclusione, O(n) della verifica universale")
    scala = bench_scale()
    _write_csv(ARTIFACTS / "scala.csv", scala)

    # Riepilogo leggibile: stesso contenuto dei CSV, incolonnato.
    head = [
        "RISULTATI DELLA MISURA DELLE PRESTAZIONI", "=" * 78,
        f"Piattaforma: {platform.platform()}",
        f"Python {platform.python_version()}  -  pyca/cryptography {cryptography.__version__}",
        f"RSA {crypto.RSA_KEY_SIZE} bit (e={crypto.RSA_PUBLIC_EXPONENT});  hash SHA-256;  "
        "firma RSA-PSS (MGF1-SHA256, salt di lunghezza massima)",
        "Tempi di interazione = sola elaborazione per passo (trasporto in-process, senza latenza di rete).",
        "Dimensioni dei messaggi = serializzazione binaria canonica lunghezza-prefissata.",
        f"Sezione 2 misurata con id_elezione='{ID_ELEZIONE}'.  Sezione 3 su un'urna sintetica:",
        "record e catena reali e firmati, K_j/F_j casuali, pubblicazione a finestra singola.",
        "",
    ]
    sezioni = [
        ("1) Costo delle singole primitive crittografiche  (primitive_tempi.csv)", prim),
        ("2a) Tempi di interazione per passo + latenza delle verifiche  (e2e_tempi.csv)", e2e_times),
        ("2b) Dimensione dei messaggi scambiati  (e2e_dimensioni.csv)", e2e_sizes),
        ("3) Scala di un ateneo: O(log n) prova di inclusione, O(n) verifica universale  (scala.csv)", scala),
    ]
    lines = list(head)
    for titolo, righe in sezioni:
        lines.append(f"## {titolo}")
        lines.extend(_aligned(righe))
        lines.append("")
    (ARTIFACTS / "RISULTATI_BENCHMARK.txt").write_text("\n".join(lines), encoding="utf-8")

    print("\n" + "=" * 78)
    print(f"Artefatti in: {ARTIFACTS}")
    for p in sorted(ARTIFACTS.iterdir()):
        print(f"  - {p.name}")
    print("Tabelle incolonnate complete: artifacts/RISULTATI_BENCHMARK.txt")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
