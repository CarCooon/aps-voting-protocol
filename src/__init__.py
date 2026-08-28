"""src - implementazione simulata del protocollo di voto elettronico progettato in WP2.

Un modulo per attore, piu' alcuni moduli di supporto.

    crypto      primitive (RSA-2048, RSA-OAEP, hash-and-sign RSA-PSS, SHA-256,
                CSPRNG) + serializzazione canonica lunghezza-prefissata per le firme
    merkle      Merkle Tree con domain separation foglia/nodo (RFC 6962-style)
    messages    strutture dati del protocollo con la notazione di WP2
                (Params/Record_0, C_p, M, R, Record_j, Invalid_j, Record_chiusura,
                 CoSignedRoot, Doc_finale)
    sim         astrazioni di simulazione dichiarate: rete/TLS, PKI/X.509, IdP
                (OIDC/SSO/MFA), orologio
    sa          Sistema di Autenticazione
    urn         Urna pubblica ibrida (hash chain + indice Merkle, finestre)
    ae          Autorita' Elettorale (5 controlli, ricevuta, scrutinio black-box)
    voter       Elettore (Fasi 1-2, [VER-1])
    verifier    Verificatore Pubblico ([VER-2])
    election    orchestratore

Ogni modulo cita, nelle docstring, le sezioni di WP2/WP3 che realizza.
"""

__all__ = ["crypto", "merkle", "messages", "sim", "sa", "urn", "ae", "voter", "verifier", "election"]
