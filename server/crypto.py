"""AES-256-GCM encryption and session key management for the tunnel.

Design notes
------------
* The *master key* is shared by every client and the server.  It never travels
  over the wire.
* Each connection performs a PSK style handshake (``HELLO`` / ``HELLO_ACK``)
  carrying HMAC proofs.  A client that does not know the master key cannot
  produce a valid proof, and a replayed handshake is useless because it
  derives a brand new session key.
* The session key is derived with HKDF-SHA256 from the master key and four
  fresh random values, so the traffic of one session never repeats a key.
* Every frame is sealed with AES-256-GCM.  The 12 byte nonce is
  ``session id (8 random bytes) || counter (4 bytes)``.  The two directions
  use different session ids, so the nonce is unique for the whole session
  without any random draw per frame.
* The frame header is authenticated as GCM Additional Authenticated Data.
"""

import hashlib
import hmac
import os
import secrets
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

from .protocol import HEADER_LEN, NONCE_LEN, TAG_LEN

KEY_LEN = 32
SESSION_ID_LEN = 8
CLIENT_ID_LEN = 8
NONCE_LEN = 12
PROOF_LEN = 16

MASTER_KEY_ENV = "TRAFFIC_INSPECTOR_KEY"
DEFAULT_ENV_FILE = ".env"
CONTEXT = b"traffic-inspector/1"

HELLO_TAG = b"ti-hello-v1"
ACK_TAG = b"ti-ack-v1"


class CryptoError(Exception):
    """Raised when a frame cannot be authenticated or a key is unusable."""


# --- master key ------------------------------------------------------------
def _decode_key(raw):
    raw = raw.strip()
    if len(raw) == KEY_LEN * 2:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    data = raw.encode("utf-8")
    if len(data) < KEY_LEN:
        data = data + b"\0" * (KEY_LEN - len(data))
    return data[:KEY_LEN]


def load_master_key(env_file=None, create=True):
    """Load the shared master key.

    Order of preference: the ``TRAFFIC_INSPECTOR_KEY`` environment variable,
    then a ``KEY=value`` line in the env file, and finally a freshly generated
    key which is written back to the env file.
    """
    env_path = Path(env_file or DEFAULT_ENV_FILE)

    raw = os.environ.get(MASTER_KEY_ENV)
    if raw:
        return _decode_key(raw)

    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(MASTER_KEY_ENV + "="):
                return _decode_key(line.split("=", 1)[1])

    if not create:
        raise CryptoError(
            "no master key found: set %s or create %s" % (MASTER_KEY_ENV, env_path)
        )

    key = secrets.token_bytes(KEY_LEN)
    env_path.write_text(
        "# traffic-inspector master key (shared secret, keep it safe)\n"
        "%s=%s\n" % (MASTER_KEY_ENV, key.hex()),
        encoding="utf-8",
    )
    try:
        os.chmod(env_path, 0o600)
    except OSError:
        pass  # not supported on every platform (Windows)
    return key


# --- proofs and key derivation --------------------------------------------
def hello_proof(master, client_id, client_nonce):
    return hmac.new(master, HELLO_TAG + client_id + client_nonce, hashlib.sha256).digest()[:PROOF_LEN]


def ack_proof(master, client_id, server_id, client_nonce, server_nonce):
    message = ACK_TAG + client_id + server_id + client_nonce + server_nonce
    return hmac.new(master, message, hashlib.sha256).digest()[:PROOF_LEN]


def derive_session_key(master, client_id, server_id, client_nonce, server_nonce):
    """Derive the per session traffic key from the master key."""
    salt = client_id + server_id + client_nonce + server_nonce
    return HKDF(master, KEY_LEN, salt, SHA256, context=CONTEXT)


# --- sealing ---------------------------------------------------------------
def seal(key, nonce, header, payload):
    """Seal ``payload`` and return the full wire frame (header included)."""
    if len(nonce) != NONCE_LEN:
        raise CryptoError("nonce must be %d bytes" % NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(header)  # header is authenticated, not encrypted
    ciphertext, tag = cipher.encrypt_and_digest(payload)
    return header + nonce + ciphertext + tag


def unseal(key, wire):
    """Verify and decrypt a wire frame.  Returns ``(header, payload)``."""
    if len(wire) < HEADER_LEN + NONCE_LEN + TAG_LEN:
        raise CryptoError("frame too short")
    header = wire[:HEADER_LEN]
    nonce = wire[HEADER_LEN:HEADER_LEN + NONCE_LEN]
    ciphertext = wire[HEADER_LEN + NONCE_LEN:-TAG_LEN]
    tag = wire[-TAG_LEN:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(header)
    try:
        payload = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise CryptoError("authentication failed (%s)" % exc)
    return header, payload


def seal_with_master(master, header, payload):
    """Seal a handshake frame with the master key and a random nonce."""
    return seal(master, secrets.token_bytes(NONCE_LEN), header, payload)


def unseal_with_master(master, wire):
    return unseal(master, wire)


class SessionCrypto:
    """Encrypts and decrypts frames for one tunnel session."""

    def __init__(self, key, send_id, recv_id):
        self.key = key
        self.send_id = send_id
        self.recv_id = recv_id
        self._send_counter = 0
        self._recv_counter = 0

    def encrypt(self, header, payload):
        nonce = self.send_id + self._send_counter.to_bytes(4, "big")
        self._send_counter += 1
        return seal(self.key, nonce, header, payload)

    def decrypt(self, wire):
        expected = self.recv_id + self._recv_counter.to_bytes(4, "big")
        actual = wire[HEADER_LEN:HEADER_LEN + NONCE_LEN]
        if actual != expected:
            raise CryptoError("unexpected nonce (replay or reordered frame)")
        self._recv_counter += 1
        return unseal(self.key, wire)
