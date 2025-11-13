# vpn_common.py
import os
import struct
import threading
import time
from dataclasses import dataclass
from typing import Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import secrets

# --- Config ---
NONCE_SIZE = 12
SEQ_FMT = "!Q"
HEADER_FMT = "!QB"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

MSG_TYPE_DATA = 0
MSG_TYPE_REKEY_REQ = 1
MSG_TYPE_REKEY_RESP = 2
MSG_TYPE_TERMINATE = 3
MSG_TYPE_HANDSHAKE = 4

REKEY_HMAC_INFO = b"REKEY-HMAC"
SESSION_KEY_INFO = b"VPN-SESSION-KEY"
REKEY_CONFIRM_INFO = b"REKEY-CONFIRM"

REKEY_BYTES = 1024 * 1024
REKEY_SECONDS = 300

# --- Crypto helpers ---
def hkdf_sha256(shared_secret: bytes, salt: Optional[bytes] = None, info: bytes = SESSION_KEY_INFO, length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(shared_secret)

def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()

def generate_x25519_keypair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    priv = x25519.X25519PrivateKey.generate()
    return priv, priv.public_key()

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = crypto_hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def aesgcm_encrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes = None) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, data, aad)

def aesgcm_decrypt(key: bytes, nonce: bytes, ct: bytes, aad: bytes = None) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, aad)

# Packet helpers
def pack_message(seq: int, msg_type: int, nonce: bytes, ciphertext: bytes) -> bytes:
    header = struct.pack(HEADER_FMT, seq, msg_type)
    return header + nonce + ciphertext

def unpack_message(blob: bytes):
    if len(blob) < HEADER_SIZE + NONCE_SIZE:
        raise ValueError("Message too short")
    header = blob[:HEADER_SIZE]
    seq, msg_type = struct.unpack(HEADER_FMT, header)
    nonce = blob[HEADER_SIZE:HEADER_SIZE + NONCE_SIZE]
    ciphertext = blob[HEADER_SIZE + NONCE_SIZE:]
    return seq, msg_type, nonce, ciphertext

# Nonce counter: 12 bytes (4 zero + 8-byte counter)
class NonceCounter:
    def __init__(self):
        self.counter = 0
        self.lock = threading.Lock()
    def next(self) -> bytes:
        with self.lock:
            self.counter += 1
            return (0).to_bytes(4, 'big') + self.counter.to_bytes(8, 'big')

@dataclass
class KeyState:
    key: bytes
    send_seq: int = 0
    recv_seq: int = 0
    bytes_transferred: int = 0
    last_rekey_time: float = time.time()
    nonce_counter: NonceCounter = None
    def __post_init__(self):
        if self.nonce_counter is None:
            self.nonce_counter = NonceCounter()

# Serialization helpers
def ed25519_serialize_pub(pub: ed25519.Ed25519PublicKey) -> bytes:
    return pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

def ed25519_serialize_priv(priv: ed25519.Ed25519PrivateKey) -> bytes:
    return priv.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())

def ed25519_load_pub(raw: bytes) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)

def ed25519_load_priv(raw: bytes) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)

def x25519_serialize_pub(pub: x25519.X25519PublicKey) -> bytes:
    return pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

def x25519_load_pub(raw: bytes) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(raw)

def secure_compare(a: bytes, b: bytes) -> bool:
    return secrets.compare_digest(a, b)
