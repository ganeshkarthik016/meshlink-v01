"""A node: listens for peers, keeps the peer table, floods chat.

Threads:
  - one accept thread (waits for incoming connections)
  - one short-lived thread per incoming connection, which does the handshake
    and then becomes that peer's receiver loop
  - one receiver thread per outgoing connection (started by connect())
  - whatever thread calls send_chat() / connect() (the prompt, later)

The peer table has one lock. It is only ever held for quick dictionary work,
never while sending or receiving on a socket.
"""

import logging
import os
import socket
import threading

from p2pchat import config
from p2pchat.chat import ChatError, decode_chat, encode_chat
from p2pchat.crypto import CryptoError, decrypt_packet, encrypt_packet
from p2pchat.framing import FrameError
from p2pchat.packet import PacketError, PacketType, new_message_id
from p2pchat.peer import ConnType, HandshakeError, Peer, Role
from p2pchat.seen_cache import SeenCache

log = logging.getLogger(__name__)


def new_node_id() -> bytes:
    """A fresh random node ID. (In v0.1 a node gets a new one on every start.)"""
    return os.urandom(config.SENDER_ID_SIZE)


class Node:
    def __init__(self, node_id, handshake_key, message_key, nickname, on_chat,
                 host="0.0.0.0", port=config.MESH_PORT):
        """on_chat(sender_id, nickname, text) is called, from a receiver thread,
        for every new chat message from another node."""
        self.node_id = node_id
        self.nickname = nickname
        self.port = port   # becomes the real port after start() (useful with port=0)
        self._handshake_key = handshake_key
        self._message_key = message_key
        self._on_chat = on_chat
        self._host = host
        self._lock = threading.Lock()
        self._peers = {}   # node ID -> Peer
        self._seen = SeenCache(config.SEEN_MAX_ENTRIES, config.SEEN_EXPIRY_SECONDS)
        self._server = None
        self._running = False

    # --- starting and stopping -------------------------------------------------

    def start(self) -> None:
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self._host, self.port))
        self._server.listen()
        self.port = self._server.getsockname()[1]
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self) -> None:
        self._running = False
        if self._server is not None:
            try:
                self._server.shutdown(socket.SHUT_RDWR)   # wakes up accept()
            except OSError:
                pass
            self._server.close()
        for peer in self._peer_list():
            peer.close()

    # --- the peer table ---------------------------------------------------------

    def _peer_list(self) -> list:
        with self._lock:
            return list(self._peers.values())

    def peer_count(self) -> int:
        with self._lock:
            return len(self._peers)

    def peer_info(self) -> list:
        """(node ID, address) for each connected peer, for /peers."""
        return [(peer.node_id, peer.address) for peer in self._peer_list()]

    def _initiator_id(self, peer: Peer) -> bytes:
        """The node ID of whichever side opened this connection."""
        return self.node_id if peer.role == Role.INITIATOR else peer.node_id

    def _register(self, peer: Peer) -> bool:
        """Add a handshaken peer to the table. Returns False if it was refused.

        Rules (BR4, BR5): at most PEER_MAX peers; never two links to the same
        node. If two links to one node exist (both sides connected at the same
        moment) keep the one started by the lower node ID. Both nodes apply
        the same rule, so both keep the same link.
        """
        to_close = None
        with self._lock:
            existing = self._peers.get(peer.node_id)
            if existing is None:
                if len(self._peers) >= config.PEER_MAX:
                    accepted, to_close = False, peer
                else:
                    self._peers[peer.node_id] = peer
                    accepted = True
            elif self._initiator_id(peer) < self._initiator_id(existing):
                self._peers[peer.node_id] = peer
                accepted, to_close = True, existing
            else:
                accepted, to_close = False, peer
        if to_close is not None:
            to_close.close()   # outside the lock
        return accepted

    def _unregister(self, peer: Peer) -> None:
        with self._lock:
            # Only remove this exact link. A newer link to the same node may
            # have replaced it, and that one must stay.
            if self._peers.get(peer.node_id) is peer:
                del self._peers[peer.node_id]

    # --- connecting ---------------------------------------------------------------

    def connect(self, host: str, port: int) -> bool:
        """Open a connection to another node.

        Returns True if a new link was added, False if we were already linked
        to that node. Raises HandshakeError (wrong password or room, not a node)
        or OSError (cannot reach it).
        """
        sock = socket.create_connection((host, port), timeout=config.HANDSHAKE_TIMEOUT)
        try:
            peer = Peer(sock, (host, port), self._handshake_key, self.node_id, ConnType.MESH, Role.INITIATOR)
        except OSError:
            sock.close()
            raise
        peer.handshake()   # raises HandshakeError, and closes the connection itself
        if not self._register(peer):
            return False
        threading.Thread(target=self._receive_loop, args=(peer,), daemon=True).start()
        return True

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, address = self._server.accept()
            except OSError:   # the server socket was closed by stop()
                break
            if self.peer_count() >= config.PEER_MAX:
                conn.close()
                continue
            threading.Thread(target=self._serve_incoming, args=(conn, address), daemon=True).start()

    def _serve_incoming(self, conn, address) -> None:
        try:
            peer = Peer(conn, address, self._handshake_key, self.node_id, ConnType.MESH, Role.RESPONDER)
        except OSError:
            conn.close()
            return
        try:
            peer.handshake()
        except HandshakeError as error:
            log.info("handshake with %s failed: %s", address, error)
            return
        if self._register(peer):
            self._receive_loop(peer)   # this thread now serves this peer

    # --- receiving ------------------------------------------------------------------

    def _receive_loop(self, peer: Peer) -> None:
        try:
            while True:
                try:
                    packet = peer.recv_packet()
                except PacketError as error:
                    # Frames are intact but the packet inside is bad. Skip it.
                    log.warning("bad packet from %s: %s", peer.address, error)
                    continue
                self._handle_packet(peer, packet)
        except (OSError, FrameError) as error:   # includes ConnectionClosed
            log.info("peer %s gone: %s", peer.address, error)
        finally:
            self._unregister(peer)
            peer.close()

    def _handle_packet(self, peer: Peer, packet) -> None:
        # Order matters (BR2): authenticate first, then mark as seen. Marking a
        # packet seen before it is verified would let a forged packet with a
        # copied ID block the real one.
        if packet.type != PacketType.CHAT:
            log.debug("ignoring packet type %s", packet.type)
            return
        try:
            plaintext = decrypt_packet(self._message_key, packet)
        except CryptoError:
            log.warning("dropping packet from %s that failed authentication", peer.address)
            return
        if not self._seen.add(packet.message_id):   # check and insert in one step
            return   # we have already handled this one
        try:
            nickname, text = decode_chat(plaintext)
        except ChatError as error:
            log.warning("dropping bad chat message: %s", error)
            return
        try:
            self._on_chat(packet.sender_id, nickname, text)
        except Exception:   # a bug in the callback must not kill the receiver thread
            log.exception("on_chat callback failed")
        self._forward(packet, came_from=peer)

    def _forward(self, packet, came_from: Peer) -> None:
        onward = packet.forwarded()   # None when TTL is used up
        if onward is None:
            return
        for peer in self._peer_list():
            if peer is not came_from:
                self._send_quietly(peer, onward)

    def _send_quietly(self, peer: Peer, packet) -> None:
        try:
            peer.send_packet(packet)
        except OSError as error:
            log.info("send to %s failed: %s", peer.address, error)
            peer.close()   # its receiver thread will notice and clean up

    # --- sending ----------------------------------------------------------------------

    def send_chat(self, text: str) -> int:
        """Send a chat message to all peers. Returns how many peers it went to.

        Raises ChatError (a ValueError) if the text is empty or too long.
        """
        payload = encode_chat(self.nickname, text)
        packet = encrypt_packet(
            self._message_key,
            packet_type=PacketType.CHAT,
            ttl=config.INITIAL_TTL,
            message_id=new_message_id(),
            sender_id=self.node_id,
            plaintext=payload,
        )
        self._seen.add(packet.message_id)   # so our own message is not shown again if it loops back
        peers = self._peer_list()
        for peer in peers:
            self._send_quietly(peer, packet)
        return len(peers)