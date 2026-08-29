"""Sistema di Autenticazione (SA).

Punto di controllo degli accessi: conosce le identita' reali ma non vede le
preferenze.  Autentica l'elettore come Relying Party OIDC verso l'IdP, impone
l'unicita' PER IDENTITA' (un solo C_p per elettore e per id_elezione), verifica
la proof-of-possession di PR_v (challenge-response) ed emette il certificato
pseudonimo C_p.

Il SA controfirma inoltre OGNI Merkle Root pubblicata (intermedia e definitiva),
leggendola autonomamente dalla vista pubblica dell'urna: firma solo il valore
della radice e non ha accesso al contenuto delle schede.

Non-collusione SA/AE: il registro interno `_identity_register` non e' mai
condiviso; la co-firma passa solo per la vista pubblica dell'urna.
"""

from __future__ import annotations

import time

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from . import crypto
from .messages import Certificate, CoSignedRoot
from .sim import IdToken


class AuthError(Exception):
    """Fallimento di un controllo del SA."""


class AuthServer:
    """Il SA.  `idp_pubkey` e' la chiave con cui verifica gli ID Token dell'IdP."""

    def __init__(self, id_elezione: str, idp_pubkey: RSAPublicKey, clock=time.time) -> None:
        self.id_elezione = id_elezione
        self._idp_pubkey = idp_pubkey
        self._clock = clock
        self._priv, self.public_key = crypto.generate_rsa_keypair()

        # Registro interno PER IDENTITA' REALE (mai condiviso con l'AE).
        self._identity_register: set[str] = set()
        # Challenge di proof-of-possession in sospeso: (subject_id, fp(PU_v)) -> nonce.
        self._pending: dict[tuple[str, str], bytes] = {}
        # Copia timestamptata delle Root gia' co-firmate dal SA.
        self._cosigned: dict[tuple[int, bytes], float] = {}

    # --------------------------------------------------- autenticazione ed emissione C_p
    def request_challenge(self, id_token: IdToken, pu_v_der: bytes) -> bytes:
        """Verifica l'ID Token dell'IdP (autenticita', elezione, MFA, eleggibilita'),
        controlla che l'identita' non abbia gia' ottenuto un C_p, poi emette la
        challenge (nonce casuale) per la proof-of-possession di PR_v."""
        if not id_token.verify(self._idp_pubkey):
            raise AuthError("ID Token dell'IdP non autentico")
        if id_token.id_elezione != self.id_elezione:
            raise AuthError("ID Token emesso per un'altra elezione")
        if not id_token.mfa_satisfied:
            raise AuthError("MFA non soddisfatta")
        if not id_token.eligible:
            raise AuthError("utente non avente diritto per questa elezione")
        if id_token.subject_id in self._identity_register:
            raise AuthError("certificato gia' emesso per questa identita'")
        try:
            crypto.public_key_from_der(pu_v_der)
        except (ValueError, TypeError) as exc:
            raise AuthError("PU_v presentata non valida") from exc

        nonce = crypto.csprng_bytes(32)
        self._pending[(id_token.subject_id, crypto.sha256_hex(pu_v_der))] = nonce
        return nonce

    def issue_certificate(self, id_token: IdToken, pu_v_der: bytes, pop_signature: bytes) -> Certificate:
        """Verifica la proof-of-possession di PR_v ed emette C_p.

        Controlla Sign_PR_v(H(nonce)) con la PU_v presentata; se valida emette
        C_p = { PU_v, id_elezione, Sign_PR_SA(H(PU_v || id_elezione)) } e aggiorna
        il registro interno."""
        key = (id_token.subject_id, crypto.sha256_hex(pu_v_der))
        nonce = self._pending.get(key)
        if nonce is None:
            raise AuthError("nessuna challenge in sospeso per questa sessione")

        # Ricontrollo dell'unicita' (difesa contro doppia richiesta concorrente).
        if id_token.subject_id in self._identity_register:
            del self._pending[key]
            raise AuthError("certificato gia' emesso per questa identita'")

        pu_v = crypto.public_key_from_der(pu_v_der)  # gia' validata in request_challenge
        if not crypto.verify(pu_v, nonce, pop_signature):
            raise AuthError("proof-of-possession di PR_v non valida")

        cert = Certificate.create(pu_v, self.id_elezione, self._priv)
        self._identity_register.add(id_token.subject_id)
        del self._pending[key]
        return cert

    # ----------------------------------------------- co-firma delle Merkle Root
    def cosign_roots(self, urn_view) -> list[CoSignedRoot]:
        """Legge le Merkle Root pubblicate dall'urna e appone Sign_PR_SA a quelle
        non ancora co-firmate.  NESSUN dato proviene dall'AE: solo dalla vista
        pubblica.  Restituisce le Root co-firmate perche' l'urna le ripubblichi."""
        out: list[CoSignedRoot] = []
        for root in urn_view.published_roots():
            marker = (root.window_index, root.root)
            if marker in self._cosigned:
                continue
            if not root.verify_ae(urn_view.ae_public_key()):
                raise AuthError("Root pubblicata senza firma AE valida: il SA non co-firma")
            out.append(root.with_sa_signature(self._priv))
            self._cosigned[marker] = self._clock()
        return out

    # -------------------------------------------------------------- ispezione
    def issued_count(self) -> int:
        """Numero di C_p emessi: usato solo per il confronto amministrativo
        k_totale <= C_p emessi, non e' un meccanismo pubblico."""
        return len(self._identity_register)
