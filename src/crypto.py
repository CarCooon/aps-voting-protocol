"""Primitive crittografiche e serializzazione canonica per le firme.

Lo schema di firma, denotato Sign_PR(H(x)), e' istanziato concretamente con
RSA-PSS (MGF1-SHA256): una forma probabilistica e provabilmente sicura (Random
Oracle Model) dello schema hash-and-sign.  SHA-256 e' l'hash interno, applicato
UNA SOLA VOLTA:

    Sign_PR(H(x))  ==  RSA-PSS-Sign(PR, x)   con SHA-256

Serializzazione canonica (`wire`): codifica lunghezza-prefissata (TLV) dei campi
di una struttura firmata. I campi concatenati prima dell'hash devono essere
codificati in modo univoco, cosi' che tuple di campi diverse non producano lo
stesso digest. La stessa funzione produce la forma binaria usata anche per
misurare la dimensione dei messaggi (DER per le chiavi, byte grezzi per
digest/ciphertext/firme, +5 byte di framing per campo).

Dipendenze: solo standard library + `cryptography` (pyca).
"""

from __future__ import annotations

import hashlib
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

# Dimensione del modulo RSA: 2048 bit (standard corrente).
RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537

# Nonce eta: 256 bit.
NONCE_BYTES = 32

# Codifica del voto i in {1..N}: intero big-endian a larghezza fissa prima di OAEP.
VOTE_INT_WIDTH = 4

# RSA-PSS con salt di lunghezza massima (padding.PSS.MAX_LENGTH), come nello
# schema di firma dell'esercitazione sulla cifratura ibrida.
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


# --------------------------------------------------------------------- hash / RNG
def sha256(data: bytes) -> bytes:
    """H(.) del protocollo: SHA-256, output grezzo di 32 byte."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def csprng_bytes(n: int) -> bytes:
    """Byte casuali da CSPRNG (stdlib `secrets`, entropia dell'OS)."""
    return secrets.token_bytes(n)


def fresh_nonce() -> bytes:
    """eta <- {0,1}^256 tramite CSPRNG."""
    return csprng_bytes(NONCE_BYTES)


# ------------------------------------------------------------- generazione chiavi
def generate_rsa_keypair() -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Coppia RSA-2048. Usata per (PU_ele,PR_ele), (PU_AE,PR_AE), (PU_SA,PR_SA) e (PU_v,PR_v)."""
    priv = rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE)
    return priv, priv.public_key()


# --------------------------------------------------------------- RSA-OAEP (schede)
def oaep_encrypt(pub: RSAPublicKey, plaintext: bytes) -> bytes:
    """C = RSA-OAEP-Enc(pub, plaintext; r).  Il fattore di casualita' r e' interno
    alla libreria e non e' mai esposto all'applicazione: il requisito di
    cancellazione di r e' quindi soddisfatto per costruzione."""
    return pub.encrypt(plaintext, _OAEP)


def oaep_decrypt(priv: RSAPrivateKey, ciphertext: bytes) -> bytes:
    """i = RSA-OAEP-Dec(priv, C).  Solleva ValueError se il padding non e' valido
    (usato a scrutinio per marcare Invalid_j)."""
    return priv.decrypt(ciphertext, _OAEP)


# ------------------------------------------------------ firma digitale hash-and-sign
def sign(priv: RSAPrivateKey, message: bytes) -> bytes:
    """Sign_PR(H(message)) istanziato come RSA-PSS su `message` (SHA-256 interno)."""
    return priv.sign(message, _PSS, hashes.SHA256())


def verify(pub: RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """True se `signature` e' una firma valida di `message` sotto `pub`."""
    try:
        pub.verify(signature, message, _PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------- (de)serializzazione chiavi
def public_key_to_der(pub: RSAPublicKey) -> bytes:
    """SubjectPublicKeyInfo DER: forma binaria realistica di PU_v dentro C_p e
    delle chiavi "on the wire" (dimensioni misurate su DER, non hex/PEM)."""
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_from_der(der: bytes) -> RSAPublicKey:
    key = serialization.load_der_public_key(der)
    if not isinstance(key, RSAPublicKey):
        raise TypeError("chiave pubblica non RSA")
    return key


def public_key_fingerprint(pub: RSAPublicKey) -> str:
    """Hash esadecimale della codifica DER: identificatore compatto di una chiave
    (usato nei registri interni di SA/AE per confronti di uguaglianza leggibili)."""
    return sha256_hex(public_key_to_der(pub))


# ========================================================================
#  Serializzazione canonica lunghezza-prefissata (TLV)
# ========================================================================
#   ogni campo:  tag (1 byte) || len (4 byte big-endian) || value
#   tag: 0x01 bytes grezzi | 0x02 intero >= 0 (8 byte BE) | 0x03 stringa UTF-8
#        0x04 sequenza (value = concatenazione TLV degli elementi)
# La codifica e' iniettiva anche per i campi a lunghezza variabile (liste e
# sequenze): tuple di lunghezze diverse non collidono.

_TAG_BYTES, _TAG_INT, _TAG_STR, _TAG_SEQ = 0x01, 0x02, 0x03, 0x04


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + len(value).to_bytes(4, "big") + value


def _encode(field) -> bytes:
    if isinstance(field, bool):  # bool prima di int (ne e' sottoclasse)
        return _tlv(_TAG_INT, (1 if field else 0).to_bytes(8, "big"))
    if isinstance(field, bytes):
        return _tlv(_TAG_BYTES, field)
    if isinstance(field, int):
        if field < 0:
            raise ValueError("solo interi non negativi nelle strutture firmate")
        return _tlv(_TAG_INT, field.to_bytes(8, "big"))
    if isinstance(field, str):
        return _tlv(_TAG_STR, field.encode("utf-8"))
    if isinstance(field, (list, tuple)):
        return _tlv(_TAG_SEQ, b"".join(_encode(x) for x in field))
    raise TypeError(f"tipo di campo non serializzabile: {type(field)!r}")


def wire(fields: list | tuple) -> bytes:
    """Serializzazione canonica di una struttura firmata: concatenazione TLV
    ordinata dei suoi campi, nell'ordine in cui la struttura li elenca.  Usata sia
    per calcolare i byte da firmare/hashare sia per misurare la dimensione binaria
    dei messaggi."""
    return b"".join(_encode(f) for f in fields)


def _decode_one(buf: bytes, off: int):
    if off + 5 > len(buf):
        raise ValueError("serializzazione TLV troncata: intestazione incompleta")
    tag = buf[off]
    length = int.from_bytes(buf[off + 1 : off + 5], "big")
    start, end = off + 5, off + 5 + length
    if end > len(buf):
        raise ValueError("serializzazione TLV troncata: valore incompleto")
    raw = buf[start:end]
    if tag == _TAG_BYTES:
        return raw, end
    if tag == _TAG_INT:
        return int.from_bytes(raw, "big"), end
    if tag == _TAG_STR:
        return raw.decode("utf-8"), end
    if tag == _TAG_SEQ:
        items, o = [], 0
        while o < len(raw):
            item, o = _decode_one(raw, o)
            items.append(item)
        return items, end
    raise ValueError(f"tag TLV sconosciuto: {tag}")


def unwire(buf: bytes) -> list:
    """Inversa di `wire`: ricostruisce la lista di campi da una serializzazione
    TLV.  Solleva ValueError se il buffer e' troncato o contiene un tag ignoto."""
    fields, off = [], 0
    while off < len(buf):
        field, off = _decode_one(buf, off)
        fields.append(field)
    return fields
