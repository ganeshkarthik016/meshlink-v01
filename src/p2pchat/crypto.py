"""Keys derived from the room password.

Nothing here touches the network. Later this file will also hold the
handshake proof and the encrypt/decrypt functions.
"""

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from p2pchat import config

HANDSHAKE_LABEL = b"p2pchat/handshake"
MESSAGE_LABEL = b"p2pchat/message"


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