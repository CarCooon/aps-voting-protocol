# aps-voting-protocol — scelte implementative

Implementazione in ambiente simulato del protocollo di voto elettronico
progettato in WP2, con misura delle prestazioni. Un solo processo Python;
librerie: standard library + `cryptography` (pyca), `pytest` per i test.

- `src/` — 10 moduli (un modulo per attore + supporto + orchestratore)
- `main.py` — elezione dimostrativa (happy path, 100 elettori)
- `use_cases/` — `happy_path`, `adversary_cases`, `benchmark`
- `tests/` — 59 test `pytest`
- `artifacts/` — output del benchmark (fonte autoritativa dei numeri)

Ambiente di riferimento: Python 3.14.3, `cryptography` 50.0.1, `pytest` 9.1.1.

Questo documento raccoglie il minimo indispensabile sulle scelte; il dettaglio
sta nel codice e nella documentazione dei work package.

---

## 1. Architettura

Un modulo per attore, quattro moduli di supporto, un orchestratore.

```
src/
  crypto.py    keygen RSA-2048, RSA-OAEP, hash-and-sign RSA-PSS, SHA-256, CSPRNG,
               serializzazione canonica lunghezza-prefissata (wire/unwire).
               Non dipende da nessun altro modulo del pacchetto.
  merkle.py    Merkle Tree sui fingerprint F_j, prove di inclusione O(log n).
  messages.py  una dataclass per struttura del protocollo; ognuna espone
               signed_bytes() e verify(); i blocchi di catena anche block_digest().
  sim.py       astrazioni dichiarate: SimClock, CertificateAuthority (X.509),
               open_tls_channel, IdentityProvider (OIDC/SSO/MFA), IdToken.
  sa.py        Sistema di Autenticazione
  urn.py       Urna pubblica ibrida (hash chain + indice Merkle, pubblicazione
               per finestre, Root co-firmate) + UrnView (sola lettura)
  ae.py        Autorita' Elettorale + KeyCustodian (PR_ele offline)
  voter.py     Elettore (costruzione scheda + verifica individuale)
  verifier.py  Verificatore Pubblico (verifica universale)
  election.py  orchestratore + demo_parameters()
```

Scelte trasversali: nessun raccoglitore di metriche (gli scenari misurano con
`time.perf_counter` in variabili locali); nessun decoratore; un unico
`signed_bytes()` per struttura, sorgente di verita' del digest firmato (nessuna
divergenza fra mittente e verificatore).

### Assunzioni di fiducia di WP1 rese visibili nel codice

- **Non-collusione SA/AE.** Registri interni separati e mai condivisi
  (`AuthServer._identity_register` da un lato; `ElectoralAuthority._ephemeral_register`,
  `_nonce_register`, `_archive` dall'altro). La co-firma delle Merkle Root passa
  per `AuthServer.cosign_roots(urn.view())`: il SA legge la radice dalla sola
  vista pubblica dell'urna; `Election._sync_cosign` non trasferisce dati privati.
- **PR_ele non disponibile fino a t_chiusura.** Il costruttore di
  `ElectoralAuthority` non riceve `PR_ele`; un `KeyCustodian` la rilascia solo via
  `activate_tally_key()`, che rifiuta se `now < t_chiusura` o urna ancora aperta.
- **Transizione a t_chiusura esplicita nel chiamante.** `Election.close_and_tally()`
  non tocca l'orologio: a seggi ancora aperti solleva `RuntimeError`. E' lo
  scenario/test ad avanzare il tempo (`election.clock.set(params.t_chiusura + 1)`)
  prima della chiusura.
- **Modello one-shot irrevocabile.** Nessuna API di revoca o sostituzione; un
  secondo `M` con lo stesso `PU_v` e' respinto dal Controllo 3.

### Urna pubblica ibrida

- hash chain append-only: `GenesisRecord`, `VoteRecord`, `InvalidRecord`,
  `ClosureRecord`; ogni blocco porta `prev_hash` e la firma AE sul digest dei
  propri campi (`block_digest() = H(wire([signed_bytes, signature]))`);
- indice Merkle sui soli `F_j` dei `VoteRecord`, per prove O(log n);
- l'urna non contiene mai `C_j`: solo `K_j = H(C_j)` e `F_j = H(K_j || eta_j)`.
  I ciphertext vivono in `ElectoralAuthority._archive`, mai pubblicati;
- pubblicazione per finestre: `buffer_record()` fissa l'indice `j` all'accettazione;
  `flush_window()` accoda i `Record_j` e pubblica una Merkle Root intermedia
  (`CoSignedRoot`, firmata AE poi co-firmata SA); `close()` pubblica la Root
  definitiva e il `Record_chiusura`;
- `Invalid_j` firmati e accodati dopo la chiusura per ogni scheda non conforme.

---

## 2. Mappatura al protocollo di WP2

| Fase | Cosa | Funzioni |
|---|---|---|
| 0 Setup | 3 coppie RSA; PKI/X.509; genesi `Params`/`Record_0` firmato | `Election.setup`, `CertificateAuthority.issue`, `open_tls_channel`, `GenesisRecord.create` |
| 1 Autenticazione + `C_p` | coppia effimera; SSO/MFA (IdP); controlli SA (eleggibilita', unicita' per identita', proof-of-possession challenge-response di `PR_v`); emissione `C_p` | `Voter.authenticate`, `IdentityProvider.authenticate`, `AuthServer.request_challenge` / `issue_certificate` |
| 2 Costruzione scheda | `i` intero scalare 4 B; `C = RSA-OAEP-Enc(PU_ele, i)`; `eta <- CSPRNG`; Encrypt-then-Sign `sigma` | `Voter.build_ballot`, `crypto.oaep_encrypt`, `BallotPacket.create` |
| 3 Ricezione + ricevuta | 5 controlli sequenziali; `K_j`, `F_j`; ricevuta `R` firmata; registrazione solo su accettazione; pubblicazione differita | `ElectoralAuthority.receive_ballot`, `Receipt.create`, `PublicUrn.buffer_record`, `Voter.process_receipt` |
| 4 Chiusura | stop a `t_chiusura`; ultimo flush; `Record_chiusura`; Root definitiva co-firmata AE+SA | `ElectoralAuthority.close`, `PublicUrn.close`, `AuthServer.cosign_roots` |
| 5 Scrutinio | iniezione tardiva di `PR_ele`; `i = RSA-OAEP-Dec`; `1 <= i <= N`; `Invalid_j` firmati; conteggio aggregato; `Doc_finale` | `ElectoralAuthority.activate_tally_key` / `tally`, `PublicUrn.append_invalid`, `FinalDocument.create` |
| Verifica individuale | ricalcolo `K`/`F`; verifica `Sign_PR_AE(R)` prima di cancellare `PR_v`; Merkle proof contro la Root definitiva co-firmata (AE e SA); coerenza con `Record_j` | `Voter.process_receipt`, `Voter.verify_individual_inclusion` |
| Verifica universale | hash chain sequenziale; firme AE su ogni blocco; doppia firma AE+SA su ogni Root; Root vs `Record_chiusura` vs `Doc_finale`; `k_conformi + k_invalide = k_totale` con conteggio per tipo; corrispondenza `Invalid_j` <-> `Record_j`; autenticita' `Doc_finale` | `PublicVerifier.verify_universal` |

### Strutture dei messaggi -> `messages.py`

`signed_bytes()` restituisce i byte canonici su cui si calcola la firma (tutti i
campi tranne la firma stessa).

| WP2 | Classe | Campi firmati |
|---|---|---|
| `Params` / `Record_0` | `GenesisRecord` | `id_elezione, PU_ele(DER), N, lista_candidati, t_apertura, t_chiusura` |
| `C_p` | `Certificate` | `PU_v(DER), id_elezione` |
| `M` | `BallotPacket` | `C, C_p, eta, id_elezione` (firma effimera `sigma`) |
| `R` | `Receipt` | `K_j, F_j, j, id_elezione` |
| `Record_j` | `VoteRecord` | `j, K_j, F_j, H(Record_{j-1})` |
| `Invalid_j` | `InvalidRecord` | `id_elezione, j, K_j, motivo, H(Record_prec)` (vedi §4.3) |
| Merkle Root co-firmata | `CoSignedRoot` | solo `root` (32 B), firmata da AE e da SA |
| `Record_chiusura` | `ClosureRecord` | `k_totale, MerkleRoot_finale, H(Record_n)` |
| `Doc_finale` | `FinalDocument` | `Risultato, k_totale, k_conformi, k_invalide, Merkle_Root_finale` |

Strutture di supporto (in `sim.py`, non del protocollo di WP2): `IdToken`,
`X509Certificate`.

---

## 3. Implementato fedelmente vs simulato

### Fedele a WP1-WP3

Quattro attori con separazione dei compiti; Fasi 0-5 complete; proof-of-possession
challenge-response di `PR_v` in Fase 1; 5 controlli sequenziali di Fase 3
nell'ordine di WP2, con iscrizione nei registri solo su accettazione:

1. `t_apertura <= now <= t_chiusura` (confronto reale con l'orologio);
2. `Sign_PR_SA` su `C_p` **e** `C_p.id = M.id = elezione corrente`;
3. `PU_v` non nel registro effimeri;
4. `eta` non nel registro nonce;
5. `sigma` verificata con `PU_v` estratta dal `C_p` firmato.

Urna ibrida; co-firma SA di ogni Root letta dalla vista pubblica; pubblicazione
per finestre con `j` fissato all'accettazione; `Invalid_j` firmati e accodati;
verifica individuale che controlla `Sign_PR_AE(R)` prima di azzerare `PR_v` (se
fallisce, `PR_v` non e' cancellato); verifica universale con conteggio dei record
per tipo; scrutinio black-box (plaintext mai memorizzati ne' ricollegati a `F_j`).

Controllo amministrativo `k_totale <= C_p emessi` (`AuthServer.issued_count()`,
esercitato in `happy_path`): e' un riscontro da auditor che dispone di entrambi i
conteggi, non un controllo del Verificatore Pubblico (che violerebbe la
non-collusione SA/AE).

### Simulato / astratto - motivazione e rischio residuo

| Elemento | Stato | Rischio residuo |
|---|---|---|
| Rete / round-trip | chiamate in-process | i tempi misurati sono di sola elaborazione: nessun RTT di rete (dichiarato in ogni tabella) |
| TLS | `open_tls_channel` verifica il certificato X.509 del server; confidenzialita' del payload assunta | segretezza in transito e traffic analysis non misurabili; i test MITM manipolano i byte serializzati (`tamper`) |
| PKI / X.509 | `CertificateAuthority` firma `(subject, PU, validita')` e verifica currency + firma CA | nessuna catena di certificati, nessuna revoca/CRL/OCSP |
| IdP / OIDC / SSO / MFA | `IdentityProvider` rilascia un `IdToken` firmato con identita' + eleggibilita' + esito MFA; il SA e' Relying Party | il flusso OIDC e il cerimoniale WebAuthn non sono riprodotti passo-passo; l'MFA e' un flag firmato. Agisce solo lato SA, che conosce comunque l'identita' |
| `PR_ele` offline | `KeyCustodian` / `activate_tally_key()` rifiutano prima di `t_chiusura` o a urna aperta | garanzia procedurale (un'AE pienamente disonesta controllerebbe l'attivazione); qui e' un gate testabile |
| Fattore `r` di RSA-OAEP | non cancellabile esplicitamente | `pyca/cryptography` non espone mai `r`: generato e usato internamente. L'elettore non puo' costruirci una prova del voto - requisito soddisfatto per costruzione |
| Orologio | `SimClock` iniettabile; confronti temporali reali; transizione a `t_chiusura` esplicita nel chiamante | nessuno: cambia la sorgente del tempo, non la logica del confronto |

### Fuori perimetro (citato come lavoro futuro)

Cifratura omomorfica additiva, decifratura a soglia, mix-net verificabile,
zero-knowledge proof, blind signature, blockchain / consenso distribuito. Sono i
limiti strutturali dichiarati in WP2/WP3: lo scrutinio resta black-box affidato
all'AE come autorita' istituzionale, e la non-collusione SA/AE resta
un'assunzione organizzativa.

---

## 4. Scostamenti dalla notazione di WP2

1. **Schema di firma.** `Sign_PR(H(x))` e' istanziato con **RSA-PSS**
   (`MGF1-SHA256`, `salt_length = padding.PSS.MAX_LENGTH`), la forma
   probabilistica dell'hash-and-sign visto a lezione; il salt di lunghezza massima
   segue lo schema di firma dell'esercitazione sulla cifratura ibrida. SHA-256 e'
   l'hash interno, applicato una sola volta: si passa `wire(x)` a
   `private_key.sign(..., PSS, SHA256)`. La firma e' comunque lunga 256 byte
   (dimensione del modulo RSA-2048).
2. **Serializzazione dei campi firmati.** Codifica **lunghezza-prefissata (TLV)**
   `tag || len(4B big-endian) || value`, iniettiva anche per i campi a lunghezza
   variabile (`lista_candidati`, `Risultato`). Unica sorgente di verita'
   (`crypto.wire`); e' anche la forma su cui si misurano le dimensioni dei
   messaggi.
3. **`Invalid_j`.** WP2 scrive
   `Invalid_j = {id_elezione, j, K_j, motivo, Sign_PR_AE(H(id_elezione || j || K_j || motivo))}`.
   Essendo un blocco della hash chain, il digest firmato include anche l'hash
   pointer `H(Record_prec)`, coerentemente con `Record_j`: senza, un terzo
   potrebbe ri-agganciare un `Invalid_j` altrove nella catena senza invalidare la
   firma.
4. **Firma delle Merkle Root.** Si firma **solo il valore della radice** (32 B),
   sia lato AE (`create_ae`) sia lato SA (`with_sa_signature`). `window_index` e
   `leaf_count` sono metadati non firmati (identificazione della finestra +
   sanity-check di monotonia); il conteggio autoritativo delle foglie e'
   `k_totale` nel `Record_chiusura` firmato.
5. **Timestamp.** Nelle strutture firmate entrano come interi (microsecondi
   epoch), per una codifica canonica deterministica.
6. **Codifica del voto.** `i in {1..N}` serializzato come intero big-endian a 4
   byte prima di `RSA-OAEP-Enc`. A scrutinio: lunghezza diversa da 4 B ->
   `MALFORMED_PADDING`; `i` fuori `[1, N]` -> `OUT_OF_RANGE`; `C` non cifrato con
   `PU_ele` -> `DECRYPT_FAILED`.

---

## 5. Primitive usate -> materiale del corso

| Primitiva / meccanismo | Dove | Riferimento |
|---|---|---|
| Keygen RSA-2048 (`e = 65537`), RSA-OAEP (MGF1/SHA-256) | `crypto` | slide crittografia a chiave pubblica |
| Hash-and-sign su digest (istanza RSA-PSS, salt massimo) | `crypto.sign/verify` | slide chiave pubblica; esercitazione cifratura ibrida |
| SHA-256 (`K_j`, `F_j`, digest, firme) | `crypto`, `merkle`, `messages` | slide integrita' |
| Merkle Tree + proof of membership O(log n) | `merkle` | esercitazione `0_merkle_tree.py`: foglia `H(F_j)`, nodo `H(sx||dx)`, ultimo nodo duplicato se il livello e' dispari, prove con posizioni `left`/`right` |
| Hash pointer / hash chain / log append-only tamper-evident | `urn`, `*.block_digest` | slide integrita'; slide blockchain (append-only, Haber-Stornetta) |
| Commitment con hiding via `r` ad alta min-entropy (`K_j = H(C_j)`) | `ae.receive_ballot` | slide integrita' |
| CSPRNG per `eta` e per le challenge (`secrets`) | `crypto.csprng_bytes` / `fresh_nonce` | slide autenticazione |
| Challenge-response, nonce, freshness, anti-replay, timestamp | `sa.request_challenge`, `ae.receive_ballot` | slide autenticazione |
| Encrypt-then-Sign con identita' del mittente nel digest | `BallotPacket.create` (`sigma` copre `C_p`) | slide chiave pubblica; esercitazione cifratura ibrida |
| Verifica dell'autenticita' prima della decifratura | `ae` (`sigma` al Controllo 5, `C_j` decifrato solo a scrutinio) | esercitazioni Encrypt-then-MAC e cifratura ibrida |
| PKI / X.509 / validazione, TLS con autenticazione del server (simulati) | `sim.CertificateAuthority`, `sim.open_tls_channel` | slide distribuzione delle chiavi |
| Federated identity, OIDC/OAuth, SSO, MFA (simulati) | `sim.IdentityProvider`, `sim.IdToken` | slide autenticazione |

Librerie: standard library + `cryptography` (pyca) + `pytest`. Nessuna libreria
di nicchia. Versioni pinnate in `requirements.txt` (`cryptography==50.0.1`,
`pytest==9.1.1`).

---

## 6. Prestazioni

Tre scenari isolati in `use_cases/benchmark.py`, ciascuno con misure locali
(`time.perf_counter`), nessuno stato globale. Le dimensioni dei messaggi sono
misurate sulla serializzazione binaria (`crypto.wire`). I numeri autoritativi
sono in `artifacts/`, rigenerabili con `python use_cases/benchmark.py` (qualche
minuto). Macchina di sviluppo non isolata: contano gli ordini di grandezza e gli
andamenti, non i valori assoluti.

- **Primitive** (`primitive_tempi.csv`): dominano le operazioni con esponente
  privato - keygen RSA-2048 ~40 ms (alta varianza), decrypt e sign ~0.6 ms;
  encrypt, verify e SHA-256 sono 2-4 ordini di grandezza sotto. Il costo
  per-elettore e' quasi tutto nel keygen della coppia effimera.
- **End-to-end, 60 elettori** (`e2e_tempi.csv`, `e2e_dimensioni.csv`):
  autenticazione + `C_p` ~50 ms/elettore (keygen effimero); costruzione scheda e
  ricezione sotto 1 ms; verifica individuale ~0.3 ms; verifica universale su 60
  record ~3.4 ms. `M` ~1156 B, `R` ~364 B, `Record_j` ~390 B (serializzazione
  binaria; `PU_v` DER 294 B, firma RSA-PSS 256 B, ciphertext OAEP 256 B).
- **Scala universitaria** (`scala.csv`, urna sintetica da 500 a 50 000 record):
  la Merkle proof cresce come `ceil(log2 n)` (9 -> 16 hash da 500 a 50k schede,
  288 -> 512 B); generazione e verifica della proof restano nell'ordine delle
  decine di microsecondi. La verifica universale e la verifica della sola hash
  chain crescono **linearmente** in `n` (dominate da `n` verifiche di firma RSA);
  a 30-40 000 schede - la scala dell'Ateneo - la verifica universale completa
  richiede circa 1.5-2.5 s, una tantum e fuori dal percorso di voto.

---

## 7. Test

`pytest` (config in `pyproject.toml`: `testpaths = ["tests"]`,
`pythonpath = ["."]`). Una fixture pre-genera un pool di 120 coppie RSA-2048
reali una volta per sessione, per non far dominare il keygen; i test restano
autentici.

**59 test, tutti verdi.**

| File | N | Copre |
|---|---:|---|
| `test_happy_path.py` | 6 | verifica individuale e universale positive; firma su `R` verificata prima della cancellazione; urna senza `C_j`; pubblicazione per finestre; doppia co-firma delle Root |
| `test_threat_model.py` | 18 | i 5 controlli di ricezione; MITM sui byte in transito; replay; doppio voto; doppia richiesta di `C_p`; `C_p` contraffatto; proof-of-possession invalida; elettore non avente diritto; MFA mancante; schede non conformi -> `Invalid_j` con i tre motivi; `PR_ele` non attivabile prima di `t_chiusura` |
| `test_integrity_negative.py` | 13 | snapshot valido positivo; poi negativi: record modificato/rimosso/iniettato, firma AE contraffatta, Merkle Root incoerente con `Doc_finale`, `Doc_finale` alterato, Root senza co-firma SA o con co-firma contraffatta, `Invalid_j` duplicato o per `j` inesistente; verifica individuale negativa se il proprio `F_j` sparisce o se la Root co-firmata e' alterata |
| `test_merkle.py` | 22 | roundtrip della proof su tutti gli indici per `n` in {1..100}; lunghezza `ceil(log2 n)`; l'albero si impegna sul numero di foglie; iniettivita' di `wire` sui campi a lunghezza variabile |

Scenari eseguibili oltre ai test: `python main.py` (happy path, exit 0 se le
verifiche sono positive); `python use_cases/adversary_cases.py` (sette profili
avversariali del modello di minaccia - Avversario di Rete, Attaccante DoS,
Falsario, Elettore Disonesto, Coercitore, SA Disonesto, AE Disonesta - con 21
vettori verificati e i limiti dichiarati come rischio residuo).
