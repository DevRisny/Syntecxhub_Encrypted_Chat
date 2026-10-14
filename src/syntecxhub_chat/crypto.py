"""Cryptography for Syntecxhub Chat: key exchange, authentication and message sealing.

Design
  * Key exchange: ephemeral X25519 (a new key pair for every connection -> forward secrecy)
  * Key schedule: HKDF-SHA256 over the shared secret, salted with the handshake transcript
  * Authentication: both sides prove they know the pre-shared passphrase with an HMAC over
    the transcript (stops a man-in-the-middle who does not know the passphrase)
  * Passphrase -> key: scrypt with a random per-server salt
  * Messages: AES-256-GCM. Separate key per direction. The 96-bit nonce is a 4-byte prefix
    (derived per direction) plus a strictly increasing 64-bit counter, so a nonce can never
    repeat under the same key. The receiver only accepts the next expected counter, which
    blocks replayed, dropped or reordered messages.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PROTOCOL = b"syntecxhub-chat/1"
VERSION = 1

KEY_LEN = 32
NONCE_PREFIX_LEN = 4
COUNTER_LEN = 8
TAG_LEN = 16
SALT_LEN = 16
RANDOM_LEN = 16
PUBKEY_LEN = 32
MAX_COUNTER = 2**64 - 1

CLIENT_HELLO_LEN = 1 + PUBKEY_LEN + RANDOM_LEN
SERVER_HELLO_LEN = 1 + PUBKEY_LEN + RANDOM_LEN + SALT_LEN

SCRYPT_N = 2**14  # cost of turning the passphrase into a key (r=8, p=1)


class CryptoError(Exception):
    """Any cryptographic failure (bad message, bad counter, bad handshake data)."""


class AuthError(CryptoError):
    """The other side does not know the passphrase (or is not a Syntecxhub chat peer)."""


# --------------------------------------------------------------------------
# Passphrase
# --------------------------------------------------------------------------
def derive_psk(passphrase: str, salt: bytes, n: int = SCRYPT_N) -> bytes:
    """Turn the shared passphrase into a 256-bit authentication key (scrypt)."""
    if not passphrase:
        raise CryptoError("passphrase cannot be empty")
    return Scrypt(salt=salt, length=KEY_LEN, n=n, r=8, p=1).derive(passphrase.encode("utf-8"))


# --------------------------------------------------------------------------
# Handshake messages
# --------------------------------------------------------------------------
def _new_keypair() -> Tuple[X25519PrivateKey, bytes]:
    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, public


def new_client_hello() -> Tuple[X25519PrivateKey, bytes]:
    """Client -> server: version, ephemeral public key, random value."""
    private, public = _new_keypair()
    return private, bytes([VERSION]) + public + secrets.token_bytes(RANDOM_LEN)


def parse_client_hello(data: bytes) -> bytes:
    """Return the client's public key, or raise CryptoError."""
    if len(data) != CLIENT_HELLO_LEN or data[0] != VERSION:
        raise CryptoError("bad client hello")
    return data[1 : 1 + PUBKEY_LEN]


def new_server_hello(salt: bytes) -> Tuple[X25519PrivateKey, bytes]:
    """Server -> client: version, ephemeral public key, random value, passphrase salt."""
    private, public = _new_keypair()
    return private, bytes([VERSION]) + public + secrets.token_bytes(RANDOM_LEN) + salt


def parse_server_hello(data: bytes) -> Tuple[bytes, bytes]:
    """Return (server public key, passphrase salt), or raise CryptoError."""
    if len(data) != SERVER_HELLO_LEN or data[0] != VERSION:
        raise CryptoError("bad server hello")
    public = data[1 : 1 + PUBKEY_LEN]
    salt = data[1 + PUBKEY_LEN + RANDOM_LEN :]
    return public, salt


# --------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------
class Session:
    """Encrypts outgoing and decrypts incoming messages of one connection."""

    def __init__(
        self,
        send_key: bytes,
        recv_key: bytes,
        send_prefix: bytes,
        recv_prefix: bytes,
        send_aad: bytes,
        recv_aad: bytes,
    ) -> None:
        self._send = AESGCM(send_key)
        self._recv = AESGCM(recv_key)
        self._send_prefix = send_prefix
        self._recv_prefix = recv_prefix
        self._send_aad = send_aad
        self._recv_aad = recv_aad
        self.send_counter = 0
        self.recv_counter = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        """Return counter (8 bytes) + AES-GCM ciphertext and tag."""
        if self.send_counter >= MAX_COUNTER:
            raise CryptoError("message limit reached, reconnect")
        counter = self.send_counter.to_bytes(COUNTER_LEN, "big")
        sealed = self._send.encrypt(self._send_prefix + counter, plaintext, self._send_aad)
        self.send_counter += 1
        return counter + sealed

    def decrypt(self, frame: bytes) -> bytes:
        """Check the counter and the GCM tag, then return the plaintext."""
        if len(frame) < COUNTER_LEN + TAG_LEN:
            raise CryptoError("message too short")
        counter, sealed = frame[:COUNTER_LEN], frame[COUNTER_LEN:]
        if int.from_bytes(counter, "big") != self.recv_counter:
            raise CryptoError("unexpected message counter (replayed, dropped or reordered)")
        try:
            plaintext = self._recv.decrypt(self._recv_prefix + counter, sealed, self._recv_aad)
        except InvalidTag:
            raise CryptoError("message failed authentication") from None
        self.recv_counter += 1
        return plaintext


def derive_session(
    private_key: X25519PrivateKey,
    peer_public: bytes,
    client_hello: bytes,
    server_hello: bytes,
    *,
    is_client: bool,
) -> Tuple[Session, bytes]:
    """Run ECDH + HKDF. Returns (session, transcript hash)."""
    transcript = hashlib.sha256(PROTOCOL + b"\x00" + client_hello + server_hello).digest()
    try:
        shared = private_key.exchange(X25519PublicKey.from_public_bytes(peer_public))
    except ValueError:
        raise CryptoError("invalid public key") from None
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=2 * KEY_LEN + 2 * NONCE_PREFIX_LEN,
        salt=transcript,
        info=PROTOCOL + b" key schedule",
    ).derive(shared)
    key_c2s, key_s2c = okm[:KEY_LEN], okm[KEY_LEN : 2 * KEY_LEN]
    prefix_c2s = okm[2 * KEY_LEN : 2 * KEY_LEN + NONCE_PREFIX_LEN]
    prefix_s2c = okm[2 * KEY_LEN + NONCE_PREFIX_LEN :]
    aad_c2s = PROTOCOL + b"|c2s|" + transcript
    aad_s2c = PROTOCOL + b"|s2c|" + transcript
    if is_client:
        session = Session(key_c2s, key_s2c, prefix_c2s, prefix_s2c, aad_c2s, aad_s2c)
    else:
        session = Session(key_s2c, key_c2s, prefix_s2c, prefix_c2s, aad_s2c, aad_c2s)
    return session, transcript


# --------------------------------------------------------------------------
# Passphrase authentication
# --------------------------------------------------------------------------
def auth_tag(psk: bytes, role: bytes, transcript: bytes) -> bytes:
    """HMAC proving knowledge of the passphrase for this exact handshake."""
    return hmac.new(psk, b"auth|" + role + b"|" + transcript, hashlib.sha256).digest()


def check_auth_tag(psk: bytes, role: bytes, transcript: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(auth_tag(psk, role, transcript), tag)
