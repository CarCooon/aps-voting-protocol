"""Astrazioni di simulazione: orologio, PKI/X.509, canale TLS, Identity Provider.

In un ambiente stand-alone rete, PKI/TLS e Identity Provider sono simulati; ogni
astrazione e' ridotta alla funzione che serve al protocollo.

  Orologio (`SimClock`)     sorgente del tempo pilotabile dai test/scenari; i
                            confronti temporali restano quelli reali.
  PKI / X.509 (`CertificateAuthority`, `X509Certificate`)   una CA che lega
                            (subject, chiave pubblica, validita') e li verifica;
                            nessuna catena, nessuna revoca/CRL/OCSP.
  Canale TLS (`open_tls_channel`)   chiamate in-process; modella solo
                            l'autenticazione del server (verifica del certificato
                            X.509 contro la CA).  RTT di rete non modellato: i
                            tempi misurati sono di sola elaborazione.
  Identity Provider (`IdentityProvider`, `IdToken`)   rilascia un ID Token
                            firmato con identita', eleggibilita' ed esito MFA; il
                            SA e' Relying Party.  Il flusso OIDC passo-passo e il
                            cerimoniale WebAuthn non sono riprodotti: l'MFA e' un
                            flag firmato.
"""

from __future__ import annotations

import dataclasses
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from . import crypto
from .crypto import wire
from .messages import ts_to_int


# =============================================================== A7 - orologio
class SimClock:
    """Orologio simulato controllabile: confronto temporale reale, sorgente del
    tempo pilotabile dai test/scenari (per esercitare la finestra di voto e la
    chiusura senza attese reali)."""

    def __init__(self, start: float | None = None) -> None:
        self.t = time.time() if start is None else float(start)

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds

    def set(self, t: float) -> None:
        self.t = float(t)


# =============================================================== A3 - PKI / X.509
@dataclass(frozen=True)
class X509Certificate:
    """Certificato X.509 simulato: la CA firma (subject, PU_der, validita')."""

    subject: str
    public_key_der: bytes
    not_before: float
    not_after: float
    issuer: str
    signature: bytes

    def signed_bytes(self) -> bytes:
        return wire([self.subject, self.public_key_der,
                     ts_to_int(self.not_before), ts_to_int(self.not_after), self.issuer])

    def verify(self, pu_ca: RSAPublicKey, now: float) -> bool:
        if not (self.not_before <= now <= self.not_after):
            return False
        return crypto.verify(pu_ca, self.signed_bytes(), self.signature)


class CertificateAuthority:
    """CA radice: emette e verifica certificati X.509 simulati.  Distribuisce in
    modo autentico le chiavi pubbliche dei server e li autentica sui canali "TLS"."""

    def __init__(self, name: str = "UNISA-Root-CA", clock=time.time) -> None:
        self.name = name
        self._clock = clock
        self._priv, self.public_key = crypto.generate_rsa_keypair()

    def issue(self, subject: str, public_key: RSAPublicKey, validity_seconds: int = 365 * 24 * 3600) -> X509Certificate:
        now = self._clock()
        cert = X509Certificate(subject, crypto.public_key_to_der(public_key),
                               now - 1.0, now + validity_seconds, self.name, b"")
        return dataclasses.replace(cert, signature=crypto.sign(self._priv, cert.signed_bytes()))

    def verify(self, cert: X509Certificate) -> bool:
        return cert.verify(self.public_key, self._clock())


def open_tls_channel(ca: CertificateAuthority, server_name: str, server_cert: X509Certificate) -> None:
    """Simula l'handshake TLS: fallisce se il certificato del server non e' valido.
    La confidenzialita' del payload verso osservatori esterni e' assunta (nessun
    osservatore esterno e' modellato)."""
    if not ca.verify(server_cert):
        raise ConnectionError(f"handshake TLS fallito: certificato X.509 di {server_name} non valido")


# =============================================================== A4 - IdP / OIDC
@dataclass(frozen=True)
class IdToken:
    """ID Token OIDC simulato rilasciato dall'IdP.  Attesta identita' +
    eleggibilita' + avvenuta MFA.  Il SA agisce da Relying Party e si fida di
    questa asserzione firmata dall'IdP."""

    subject_id: str
    id_elezione: str
    eligible: bool
    mfa_satisfied: bool
    issued_at: float
    signature: bytes

    def signed_bytes(self) -> bytes:
        return wire([self.subject_id, self.id_elezione,
                     1 if self.eligible else 0, 1 if self.mfa_satisfied else 0,
                     ts_to_int(self.issued_at)])

    def verify(self, pu_idp: RSAPublicKey) -> bool:
        return crypto.verify(pu_idp, self.signed_bytes(), self.signature)


class IdentityProvider:
    """SSO/OIDC d'Ateneo.  Conosce l'anagrafica degli studenti e le liste
    elettorali (identity proofing ereditato).  L'MFA (preferibilmente
    FIDO2/WebAuthn) e' modellata come flag verificato dall'IdP."""

    def __init__(self, name: str = "idp.unisa.it", clock=time.time) -> None:
        self.name = name
        self._clock = clock
        self._priv, self.public_key = crypto.generate_rsa_keypair()
        self._enrolled: dict[str, set[str]] = {}   # subject -> id_elezione per cui e' avente diritto
        self._mfa_registered: set[str] = set()     # subject con autenticatore MFA registrato

    def register_student(self, subject_id: str, eligible_elections: set[str], has_mfa: bool = True) -> None:
        self._enrolled[subject_id] = set(eligible_elections)
        if has_mfa:
            self._mfa_registered.add(subject_id)

    def authenticate(self, subject_id: str, id_elezione: str, present_mfa: bool = True) -> IdToken:
        """SSO + MFA; se superati rilascia un ID Token firmato con identita',
        eleggibilita' per `id_elezione` ed esito MFA."""
        if subject_id not in self._enrolled:
            raise PermissionError(f"utente {subject_id} sconosciuto all'IdP d'Ateneo")
        mfa_ok = present_mfa and (subject_id in self._mfa_registered)
        if not mfa_ok:
            raise PermissionError("autenticazione a piu' fattori (MFA) non soddisfatta")
        eligible = id_elezione in self._enrolled[subject_id]
        tok = IdToken(subject_id, id_elezione, eligible, mfa_ok, self._clock(), b"")
        return dataclasses.replace(tok, signature=crypto.sign(self._priv, tok.signed_bytes()))
