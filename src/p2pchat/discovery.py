"""UDP discovery: find other nodes in the same room without typing addresses.

How it works:
  - Every node listens on one UDP port.
  - A joining node broadcasts a JOIN_REQUEST containing a "room tag" (a hash of
    the room ID, so other rooms' nodes stay quiet).
  - Every node in that room that still has room for another peer answers with
    a JOIN_REPLY, sent straight back to the requester, carrying its TCP port.
  - The requester collects replies for a couple of seconds.

Discovery proves nothing. Anyone can send these packets. The handshake in
peer.py is the real gate: a node with the wrong password gets found here but
fails there.

Packet (20 bytes, both kinds):
    version (1) | kind (1) | room tag (8) | node ID (8) | TCP port (2)
"""

import hashlib
import logging
import socket
import struct
import threading
import time
from typing import NamedTuple

from p2pchat import config

log = logging.getLogger(__name__)

KIND_REQUEST = 1
KIND_REPLY = 2
TAG_SIZE = 8

_PACKET = struct.Struct(f"!BB{TAG_SIZE}s{config.SENDER_ID_SIZE}sH")


class DiscoveryError(ValueError):
    """A datagram is not a valid discovery packet."""


class Candidate(NamedTuple):
    """A node that answered a search."""
    host: str
    port: int       # its TCP port
    node_id: bytes


def room_tag(room_id: str) -> bytes:
    return hashlib.sha256(room_id.encode()).digest()[:TAG_SIZE]


def encode_packet(kind: int, tag: bytes, node_id: bytes, tcp_port: int) -> bytes:
    if kind not in (KIND_REQUEST, KIND_REPLY):
        raise DiscoveryError("unknown kind")
    if len(tag) != TAG_SIZE or len(node_id) != config.SENDER_ID_SIZE:
        raise DiscoveryError("bad field size")
    if not 0 <= tcp_port <= 65535:
        raise DiscoveryError("bad port")
    return _PACKET.pack(config.PROTOCOL_VERSION, kind, tag, node_id, tcp_port)


def decode_packet(data: bytes):
    """Return (kind, tag, node_id, tcp_port). Raises DiscoveryError if bad."""
    if len(data) != _PACKET.size:
        raise DiscoveryError("wrong size")
    version, kind, tag, node_id, tcp_port = _PACKET.unpack(data)
    if version != config.PROTOCOL_VERSION:
        raise DiscoveryError("unsupported version")
    if kind not in (KIND_REQUEST, KIND_REPLY):
        raise DiscoveryError("unknown kind")
    return kind, tag, node_id, tcp_port


class Discovery:
    def __init__(self, room_id, node_id, tcp_port, can_accept, port=config.DISCOVERY_PORT):
        """tcp_port: a function returning our TCP port (it is only known once the
        node is listening). can_accept: a function returning True while we still
        have room for another peer. port: the UDP port to listen on (0 = any)."""
        self._tag = room_tag(room_id)
        self._node_id = node_id
        self._tcp_port = tcp_port
        self._can_accept = can_accept
        self.port = port
        self._sock = None
        self._thread = None
        self._running = False

    # --- answering other nodes -------------------------------------------------------------

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # REUSEADDR lets several nodes on one machine share the port.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind(("", self.port))
        except OSError:
            sock.close()
            raise
        sock.settimeout(0.05)   # so the loop notices stop() quickly
        self._sock = sock
        self.port = sock.getsockname()[1]
        self._running = True
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def _listen_loop(self) -> None:
        while self._running:
            try:
                data, address = self._sock.recvfrom(512)
            except TimeoutError:
                continue
            except ConnectionResetError:
                continue   # Windows reports an earlier unreachable send this way
            except OSError:
                break
            try:
                kind, tag, node_id, _ = decode_packet(data)
            except DiscoveryError:
                continue   # not for us: random traffic on this port
            # Only requests for OUR room, and never answer our own broadcast
            # (it loops back to us).
            if kind != KIND_REQUEST or tag != self._tag or node_id == self._node_id:
                continue
            if not self._can_accept():
                continue   # we are full: stay silent
            reply = encode_packet(KIND_REPLY, self._tag, self._node_id, self._tcp_port())
            try:
                self._sock.sendto(reply, address)
            except OSError as error:
                log.info("could not answer %s: %s", address, error)

    # --- looking for other nodes --------------------------------------------------------------

    def search(self, wait=None, targets=None) -> list:
        """Broadcast a request and collect replies. Returns a list of Candidate.

        targets: list of (host, port) to send to. The default is the broadcast
        addresses in config, on our own discovery port.
        """
        wait = config.DISCOVERY_WAIT if wait is None else wait
        if targets is None:
            targets = [(host, self.port) for host in config.BROADCAST_TARGETS]
        request = encode_packet(KIND_REQUEST, self._tag, self._node_id, self._tcp_port())

        found = {}   # node ID -> Candidate (so the same node is listed once)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind(("", 0))   # replies come back to this socket

            def send_request():
                for target in targets:
                    try:
                        sock.sendto(request, target)
                    except OSError as error:
                        log.info("could not send to %s: %s", target, error)

            start = time.monotonic()
            deadline = start + wait
            resend_at = start + wait / 2   # UDP can lose packets, so ask twice
            resent = False
            send_request()
            while True:
                now = time.monotonic()
                if now >= deadline:
                    break
                if not resent and now >= resend_at:
                    send_request()
                    resent = True
                sock.settimeout(min(0.1, deadline - now))
                try:
                    data, address = sock.recvfrom(512)
                except (TimeoutError, ConnectionResetError):
                    continue
                except OSError:
                    break
                try:
                    kind, tag, node_id, tcp_port = decode_packet(data)
                except DiscoveryError:
                    continue
                if kind != KIND_REPLY or tag != self._tag or node_id == self._node_id or tcp_port == 0:
                    continue
                found.setdefault(node_id, Candidate(address[0], tcp_port, node_id))
        return list(found.values())