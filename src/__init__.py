"""Implementazione simulata del protocollo di voto elettronico.

Un modulo per attore, piu' alcuni moduli di supporto.

    crypto      primitive (RSA-2048, RSA-OAEP, hash-and-sign RSA-PSS, SHA-256,
                CSPRNG) + serializzazione canonica lunghezza-prefissata per le firme
    merkle      Merkle Tree con prove di inclusione in tempo/spazio O(log n)
    messages    strutture dati del protocollo (Params/Record_0, C_p, M, R, Record_j,
                Invalid_j, Record_chiusura, CoSignedRoot, Doc_finale)
    sim         astrazioni di simulazione: orologio, PKI/X.509, canale TLS, IdP
                (OIDC/SSO/MFA)
    sa          Sistema di Autenticazione
    urn         Urna pubblica ibrida (hash chain + indice Merkle, pubblicazione per finestre)
    ae          Autorita' Elettorale (5 controlli, ricevuta, scrutinio black-box)
    voter       Elettore (autenticazione, costruzione della scheda, verifica individuale)
    verifier    Verificatore Pubblico (verifica universale)
    election    orchestratore
"""

__all__ = ["crypto", "merkle", "messages", "sim", "sa", "urn", "ae", "voter", "verifier", "election"]
