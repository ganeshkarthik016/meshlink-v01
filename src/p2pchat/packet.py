"""Packet format: turns a Packet object into bytes and back.

This module knows nothing about sockets or encryption. It only defines what
the header looks like and checks that bytes and fields are sane.

Layout of a flooded packet on the wire (39-byte header, then the payload):

    version (1) | type (1) | ttl (1) | message_id (16) | sender_id (8) | nonce (12) | payload

The payload is already encrypted by the time it gets here. packet.py does
not look inside it.
"""

import os
import struct
from dataclasses import dataclass, replace
from enum import IntEnum

from p2pchat import config


class PacketError(ValueError):
    """Raised when bytes or fields do not make a valid packet."""


class PacketType(IntEnum):
    CHAT = 1
    FILE_ANNOUNCE = 2


# "!" means network byte order (big-endian) with no padding between fields.
_HEADER = struct.Struct(
    f"!BBB{config.MESSAGE_ID_SIZE}s{config.SENDER_ID_SIZE}s{config.NONCE_SIZE}s"
)
HEADER_SIZE = _HEADER.size  # 39

# The part of the header that encryption will authenticate (see Packet.aad).
_AAD = struct.Struct(f"!BB{config.MESSAGE_ID_SIZE}s{config.SENDER_ID_SIZE}s")


def new_message_id() -> bytes:
    """A fresh random message ID."""
    return os.urandom(config.MESSAGE_ID_SIZE)


@dataclass(frozen=True)
class Packet:
    """One flooded packet. Frozen: to change the TTL, make a new Packet."""

    type: PacketType
    ttl: int
    message_id: bytes
    sender_id: bytes
    nonce: bytes
    payload: bytes
    version: int = config.PROTOCOL_VERSION

    def __post_init__(self):
        # Runs on every Packet, whether we built it or decoded it.
        if self.version != config.PROTOCOL_VERSION:
            raise PacketError(f"unsupported version {self.version}")
        if not isinstance(self.type, PacketType):
            raise PacketError("type must be a PacketType")
        if not isinstance(self.ttl, int) or not 0 <= self.ttl <= 255:
            raise PacketError("ttl must be an integer from 0 to 255")
        for name, value, size in (
            ("message_id", self.message_id, config.MESSAGE_ID_SIZE),
            ("sender_id", self.sender_id, config.SENDER_ID_SIZE),
            ("nonce", self.nonce, config.NONCE_SIZE),
        ):
            if not isinstance(value, bytes) or len(value) != size:
                raise PacketError(f"{name} must be exactly {size} bytes")
        if not isinstance(self.payload, bytes):
            raise PacketError("payload must be bytes")
        if len(self.payload) > config.MAX_PAYLOAD_SIZE:
            raise PacketError("payload too large")

    def encode(self) -> bytes:
        header = _HEADER.pack(
            self.version,
            int(self.type),
            self.ttl,
            self.message_id,
            self.sender_id,
            self.nonce,
        )
        return header + self.payload

    @classmethod
    def decode(cls, data: bytes) -> "Packet":
        """Parse bytes from the network. Raises PacketError on anything bad."""
        data = bytes(data)
        if len(data) < HEADER_SIZE:
            raise PacketError("packet shorter than the header")
        version, type_value, ttl, message_id, sender_id, nonce = _HEADER.unpack_from(data)
        if version != config.PROTOCOL_VERSION:
            raise PacketError(f"unsupported version {version}")
        try:
            packet_type = PacketType(type_value)
        except ValueError:
            raise PacketError(f"unknown packet type {type_value}") from None
        return cls(
            type=packet_type,
            ttl=ttl,
            message_id=message_id,
            sender_id=sender_id,
            nonce=nonce,
            payload=data[HEADER_SIZE:],
            version=version,
        )

    def aad(self) -> bytes:
        """Header bytes that encryption authenticates ("associated data").

        TTL is deliberately NOT included. Every node that forwards a packet
        lowers the TTL, and if TTL were authenticated the first relay would
        break the check. Everything else must stay exactly as the sender
        made it, so a relay cannot change the type, ID or sender unnoticed.
        """
        return _AAD.pack(self.version, int(self.type), self.message_id, self.sender_id)

    def with_ttl(self, ttl: int) -> "Packet":
        """A copy of this packet with a different TTL."""
        return replace(self, ttl=ttl)

    def forwarded(self):
        """The packet to send onward, or None if it must not be forwarded.

        Rule: forward only if the arriving TTL is greater than 1, and send
        it on with TTL minus 1. That way a packet sent with TTL n reaches
        n hops.
        """
        if self.ttl <= 1:
            return None
        return self.with_ttl(self.ttl - 1)