# aps-voting-protocol

Implementazione in ambiente simulato del protocollo di voto elettronico
verificabile progettato nei work package precedenti, con misura delle prestazioni.
Gira in un solo processo Python, senza servizi esterni.

## Struttura

| Percorso | Contenuto |
|---|---|
| `src/` | il protocollo: un modulo per attore (`voter`, `sa`, `ae`, `verifier`), le primitive e la serializzazione canonica (`crypto`), il Merkle Tree (`merkle`), le strutture dei messaggi (`messages`), le astrazioni di simulazione — rete/TLS, PKI, IdP, orologio (`sim`), l'orchestratore (`election`) |
| `main.py` | esegue l'elezione dimostrativa completa (happy path) |
| `use_cases/` | scenari eseguibili: `happy_path`, `adversary_cases` (resilienza al modello di minaccia), `benchmark` (prestazioni, scrive in `artifacts/`) |
| `tests/` | suite `pytest` |
| `artifacts/` | CSV e riepilogo prodotti dal benchmark |
| `DOCUMENTO_SCELTE_IMPLEMENTATIVE.md` | note sulle scelte implementative |

## Uso

`python main.py` &nbsp;·&nbsp; `python -m pytest` &nbsp;·&nbsp; `python use_cases/benchmark.py`

Python 3.11+ e `cryptography` (unica dipendenza; `pytest` per i test).
