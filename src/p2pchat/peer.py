"""One TCP connection to one peer: the handshake, then framed sends and receives.

peer.py does not decide what to do with packets. node.py does that.

Handshake (every TCP connection, mesh or file):
  1. Each side sends a hello: version, connection type, node ID, fresh nonce.
  2. Each side sends an HMAC proof that it holds the handshake key
     (derived from the room password). See crypto.handshake_proof.
  3. Each side checks the other's proof. A mismatch closes the connection.
"""

import hmac
import os
import socket
import struct
import threading
from enum import IntEnum

from p2pchat import config
from p2pchat.crypto import PROOF_SIZE, handshake_proof
from p2pchat.framing import FrameError, recv_frame, send_frame
from p2pchat.packet import Packet


class HandshakeError(Exception):
    """The handshake failed: wrong password, wrong room, bad data, or a timeout."""


class ConnType(IntEnum):
    MESH = 1   # long-lived chat link between peers
    FILE = 2   # short-lived download connection


class Role(IntEnum):
    INITIATOR = 1   # the side that opened the connection
    RESPONDER = 2   # the side that accepted it


# version | connection type | node ID | fresh nonce
_HELLO = struct.Struct(f"!BB{config.SENDER_ID_SIZE}s{config.HANDSHAKE_NONCE_SIZE}s")


class Peer:
    def __init__(self, sock, address, handshake_key, own_id, conn_type, role):
        self._sock = sock
        self.address = address
        self._handshake_key = handshake_key
        self.own_id = own_id
        self.conn_type = conn_type
        self.role = role
        self.node_id = None   # the other side's node ID, known after the handshake
        # Several threads may send to the same peer. This lock keeps one frame's
        # bytes together, so two frames can never be mixed up on the wire.
        self._send_lock = threading.Lock()
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)   # small chat packets go out at once
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)   # lets the OS notice a dead peer

    # --- handshake ----------------------------------------------------------

    def handshake(self) -> None:
        """Run the handshake. On success self.node_id is set. On any failure the
        connection is closed and HandshakeError is raised."""
        try:
            self._handshake()
        except HandshakeError:
            self.close()
            raise
        except (OSError, FrameError) as error:   # timeout, closed, bad frame length
            self.close()
            raise HandshakeError(f"handshake failed: {error}") from error

    def _handshake(self) -> None:
        self._sock.settimeout(config.HANDSHAKE_TIMEOUT)
        my_nonce = os.urandom(config.HANDSHAKE_NONCE_SIZE)

        send_frame(self._sock, _HELLO.pack(config.PROTOCOL_VERSION, int(self.conn_type), self.own_id, my_nonce))
        hello = recv_frame(self._sock, max_size=_HELLO.size)
        if len(hello) != _HELLO.size:
            raise HandshakeError("bad hello")
        version, their_type, their_id, their_nonce = _HELLO.unpack(hello)

        if version != config.PROTOCOL_VERSION:
            raise HandshakeError(f"unsupported version {version}")
        if their_type != self.conn_type:
            raise HandshakeError("connection type mismatch")
        if their_id == self.own_id:
            raise HandshakeError("peer has our own node ID")

        def proof(role: Role) -> bytes:
            # Same inputs on both sides, whoever computes it: the initiator's
            # nonce and ID always come first.
            if self.role == Role.INITIATOR:
                init_nonce, resp_nonce, init_id, resp_id = my_nonce, their_nonce, self.own_id, their_id
            else:
                init_nonce, resp_nonce, init_id, resp_id = their_nonce, my_nonce, their_id, self.own_id
            return handshake_proof(
                self._handshake_key,
                conn_type=int(self.conn_type),
                role=int(role),
                initiator_nonce=init_nonce,
                responder_nonce=resp_nonce,
                initiator_id=init_id,
                responder_id=resp_id,
            )

        send_frame(self._sock, proof(self.role))
        their_proof = recv_frame(self._sock, max_size=PROOF_SIZE)

        other_role = Role.RESPONDER if self.role == Role.INITIATOR else Role.INITIATOR
        if not hmac.compare_digest(their_proof, proof(other_role)):
            raise HandshakeError("wrong password or different room")

        self._sock.settimeout(None)   # from here on, receiving blocks until data arrives
        self.node_id = their_id

    # --- sending and receiving --------------------------------------------------

    def send(self, data: bytes) -> None:
        """Send one raw frame. Safe to call from several threads."""
        with self._send_lock:
            send_frame(self._sock, data)

    def recv(self) -> bytes:
        """Receive one raw frame. Call from one thread only."""
        return recv_frame(self._sock)

    def send_packet(self, packet: Packet) -> None:
        self.send(packet.encode())

    def recv_packet(self) -> Packet:
        """Receive and decode one packet. Raises PacketError on a malformed one."""
        return Packet.decode(self.recv())

    def close(self) -> None:
        # shutdown() first: it wakes up another thread that is blocked in recv().
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()