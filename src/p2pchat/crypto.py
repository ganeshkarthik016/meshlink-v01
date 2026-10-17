"""Keys, packet encryption and the handshake proof.

Nothing here touches the network.
"""

import hashlib
import hmac
import os
from dataclasses import replace

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from p2pchat import config
from p2pchat.packet import Packet, PacketType

HANDSHAKE_LABEL = b"p2pchat/handshake"
MESSAGE_LABEL = b"p2pchat/message"
PROOF_LABEL = b"p2pchat/proof"
PROOF_SIZE = 32  # HMAC-SHA256 output


class CryptoError(Exception):
    """A packet failed authentication: wrong key, or it was changed in transit."""


# --- keys -------------------------------------------------------------------

def _split_key(room_key: bytes, label: bytes) -> bytes:
    """Make one 32-byte key out of room_key. A different label gives a different key."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=label,
    ).derive(room_key)


def derive_keys(password: str, room_id: str) -> tuple[bytes, bytes]:
    """Return (handshake_key, message_key), 32 bytes each."""
    if len(password) < config.MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {config.MIN_PASSWORD_LENGTH} characters")
    if not room_id:
        raise ValueError("room ID must not be empty")

    # Slow on purpose: makes guessing passwords expensive.
    room_key = hashlib.scrypt(
        password.encode(),
        salt=room_id.encode(),
        n=config.SCRYPT_N,
        r=config.SCRYPT_R,
        p=config.SCRYPT_P,
        maxmem=config.SCRYPT_MAXMEM,
        dklen=32,
    )

    handshake_key = _split_key(room_key, HANDSHAKE_LABEL)
    message_key = _split_key(room_key, MESSAGE_LABEL)
    return handshake_key, message_key


# --- packet encryption --------------------------------------------------------

def encrypt_packet(
    message_key: bytes,
    *,
    packet_type: PacketType,
    ttl: int,
    message_id: bytes,
    sender_id: bytes,
    plaintext: bytes,
) -> Packet:
    """Encrypt plaintext and return a ready-to-send Packet.

    The header fields in Packet.aad() (everything except TTL) are authenticated,
    so changing them in transit makes decryption fail. TTL is not, because
    every relay lowers it.
    """
    nonce = os.urandom(config.NONCE_SIZE)
    # A draft with no payload, only to get the header bytes to authenticate.
    draft = Packet(
        type=packet_type,
        ttl=ttl,
        message_id=message_id,
        sender_id=sender_id,
        nonce=nonce,
        payload=b"",
    )
    ciphertext = ChaCha20Poly1305(message_key).encrypt(nonce, plaintext, draft.aad())
    return replace(draft, payload=ciphertext)


def decrypt_packet(message_key: bytes, packet: Packet) -> bytes:
    """Return the plaintext, or raise CryptoError if authentication fails."""
    try:
        return ChaCha20Poly1305(message_key).decrypt(packet.nonce, packet.payload, packet.aad())
    except InvalidTag:
        raise CryptoError("packet failed authentication") from None


# --- handshake proof ------------------------------------------------------------

def handshake_proof(
    handshake_key: bytes,
    *,
    conn_type: int,
    role: int,
    initiator_nonce: bytes,
    responder_nonce: bytes,
    initiator_id: bytes,
    responder_id: bytes,
) -> bytes:
    """Prove we hold the handshake key, without sending the password or key.

    The proof covers the connection type, our role, both fresh nonces and both
    node IDs. Fresh nonces stop a recorded proof being replayed later. Including
    the role stops a node simply echoing the other side's proof back.
    """
    if len(initiator_nonce) != config.HANDSHAKE_NONCE_SIZE or len(responder_nonce) != config.HANDSHAKE_NONCE_SIZE:
        raise ValueError("bad nonce size")
    if len(initiator_id) != config.SENDER_ID_SIZE or len(responder_id) != config.SENDER_ID_SIZE:
        raise ValueError("bad node ID size")
    message = (
        PROOF_LABEL
        + bytes([conn_type, role])
        + initiator_nonce
        + responder_nonce
        + initiator_id
        + responder_id
    )
    return hmac.new(handshake_key, message, hashlib.sha256).digest()