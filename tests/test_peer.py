import socket
import struct
import threading

import pytest

from p2pchat import config
from p2pchat.crypto import encrypt_packet
from p2pchat.framing import ConnectionClosed, send_frame
from p2pchat.packet import PacketType
from p2pchat.peer import ConnType, HandshakeError, Peer, Role

KEY = b"k" * 32
OTHER_KEY = b"o" * 32
ID_A = b"A" * config.SENDER_ID_SIZE
ID_B = b"B" * config.SENDER_ID_SIZE


def tcp_pair():
    """Two connected TCP sockets on this machine."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    client = socket.create_connection(server.getsockname())
    accepted, _ = server.accept()
    server.close()
    return client, accepted


@pytest.fixture
def sockets():
    """Hands out socket pairs and closes everything at the end of the test."""
    made = []

    def make():
        pair = tcp_pair()
        made.extend(pair)
        return pair

    yield make
    for sock in made:
        sock.close()


def make_peers(sockets, key_a=KEY, key_b=KEY, id_a=ID_A, id_b=ID_B,
               type_a=ConnType.MESH, type_b=ConnType.MESH):
    sock_a, sock_b = sockets()
    a = Peer(sock_a, "a", key_a, id_a, type_a, Role.INITIATOR)
    b = Peer(sock_b, "b", key_b, id_b, type_b, Role.RESPONDER)
    return a, b


def handshake_both(a, b):
    """Run both handshakes at the same time. Returns (error_a, error_b); None means success."""
    errors = [None, None]

    def run(index, peer):
        try:
            peer.handshake()
        except Exception as error:   # collect it so the test can look at it
            errors[index] = error

    threads = [threading.Thread(target=run, args=(0, a)), threading.Thread(target=run, args=(1, b))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    return errors[0], errors[1]


def connected_pair(sockets):
    a, b = make_peers(sockets)
    assert handshake_both(a, b) == (None, None)
    return a, b


# --- handshake: success -------------------------------------------------------------

def test_handshake_succeeds_and_each_side_learns_the_other_id(sockets):
    a, b = make_peers(sockets)
    assert handshake_both(a, b) == (None, None)
    assert a.node_id == ID_B
    assert b.node_id == ID_A


# --- handshake: failures --------------------------------------------------------------

def test_wrong_password_fails_on_both_sides(sockets):
    a, b = make_peers(sockets, key_b=OTHER_KEY)
    error_a, error_b = handshake_both(a, b)
    assert isinstance(error_a, HandshakeError)
    assert isinstance(error_b, HandshakeError)


def test_connection_type_mismatch_fails(sockets):
    a, b = make_peers(sockets, type_a=ConnType.MESH, type_b=ConnType.FILE)
    error_a, error_b = handshake_both(a, b)
    assert isinstance(error_a, HandshakeError)
    assert isinstance(error_b, HandshakeError)


def test_same_node_id_fails(sockets):
    a, b = make_peers(sockets, id_a=ID_A, id_b=ID_A)
    error_a, error_b = handshake_both(a, b)
    assert isinstance(error_a, HandshakeError)
    assert isinstance(error_b, HandshakeError)


def test_peer_closes_during_handshake(sockets):
    sock_a, sock_b = sockets()
    a = Peer(sock_a, "a", KEY, ID_A, ConnType.MESH, Role.INITIATOR)
    sock_b.close()
    with pytest.raises(HandshakeError):
        a.handshake()


def test_hello_of_the_wrong_size(sockets):
    sock_a, sock_b = sockets()
    a = Peer(sock_a, "a", KEY, ID_A, ConnType.MESH, Role.INITIATOR)
    send_frame(sock_b, b"not a hello")
    with pytest.raises(HandshakeError):
        a.handshake()


def test_unsupported_version(sockets):
    sock_a, sock_b = sockets()
    a = Peer(sock_a, "a", KEY, ID_A, ConnType.MESH, Role.INITIATOR)
    bad_hello = struct.pack(
        f"!BB{config.SENDER_ID_SIZE}s{config.HANDSHAKE_NONCE_SIZE}s",
        99, int(ConnType.MESH), ID_B, b"n" * config.HANDSHAKE_NONCE_SIZE,
    )
    send_frame(sock_b, bad_hello)
    with pytest.raises(HandshakeError):
        a.handshake()


def test_silent_peer_times_out(sockets, monkeypatch):
    monkeypatch.setattr(config, "HANDSHAKE_TIMEOUT", 0.2)
    sock_a, _ = sockets()   # the other end never answers
    a = Peer(sock_a, "a", KEY, ID_A, ConnType.MESH, Role.INITIATOR)
    with pytest.raises(HandshakeError):
        a.handshake()


# --- after the handshake ------------------------------------------------------------------

def test_packet_roundtrip(sockets):
    a, b = connected_pair(sockets)
    sent = encrypt_packet(
        b"m" * 32,
        packet_type=PacketType.CHAT,
        ttl=5,
        message_id=b"\x01" * config.MESSAGE_ID_SIZE,
        sender_id=ID_A,
        plaintext=b"hello",
    )
    a.send_packet(sent)
    assert b.recv_packet() == sent


def test_raw_frame_roundtrip_both_directions(sockets):
    a, b = connected_pair(sockets)
    a.send(b"ping")
    assert b.recv() == b"ping"
    b.send(b"pong")
    assert a.recv() == b"pong"


def test_recv_after_the_other_side_closes(sockets):
    a, b = connected_pair(sockets)
    b.close()
    with pytest.raises(ConnectionClosed):
        a.recv()


def test_close_wakes_up_a_blocked_receiver(sockets):
    a, b = connected_pair(sockets)
    outcome = []

    def receiver():
        try:
            a.recv()
        except Exception as error:
            outcome.append(error)

    thread = threading.Thread(target=receiver)
    thread.start()
    a.close()   # called from another thread while receiver() is blocked in recv()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert outcome


def test_frames_from_several_threads_never_mix(sockets):
    a, b = connected_pair(sockets)
    threads_count, per_thread = 4, 50

    def sender(number):
        for i in range(per_thread):
            a.send(bytes([number]) * 2000 + bytes([i]))   # big enough to need several sends

    threads = [threading.Thread(target=sender, args=(n,)) for n in range(threads_count)]
    for thread in threads:
        thread.start()

    for _ in range(threads_count * per_thread):
        frame = b.recv()
        assert len(frame) == 2001
        assert frame[:2000] == bytes([frame[0]]) * 2000   # all from one sender

    for thread in threads:
        thread.join(timeout=10)