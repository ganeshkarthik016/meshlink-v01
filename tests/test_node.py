import queue
import socket
import threading
import time

import pytest

from p2pchat import config
from p2pchat.chat import ChatError, encode_chat
from p2pchat.crypto import encrypt_packet
from p2pchat.node import Node
from p2pchat.packet import PacketType, new_message_id
from p2pchat.peer import ConnType, HandshakeError, Peer, Role

HS_KEY = b"h" * 32
MSG_KEY = b"m" * 32
OTHER_HS_KEY = b"x" * 32
OTHER_MSG_KEY = b"y" * 32


def ident(n):
    return bytes([n]) * config.SENDER_ID_SIZE


def wait_until(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


@pytest.fixture
def make_node():
    nodes = []
    counter = [0]

    def make(name="node", node_id=None, handshake_key=HS_KEY, message_key=MSG_KEY):
        counter[0] += 1
        received = queue.Queue()
        node = Node(
            node_id or ident(counter[0]),
            handshake_key,
            message_key,
            name,
            on_chat=lambda sender_id, nickname, text: received.put((sender_id, nickname, text)),
            host="127.0.0.1",
            port=0,
        )
        node.start()
        node.received = received   # handy in tests
        nodes.append(node)
        return node

    yield make
    for node in nodes:
        node.stop()


def link(a, b):
    """Make a connect to b and wait until both sides list each other."""
    assert a.connect("127.0.0.1", b.port) is True
    assert wait_until(lambda: a.peer_count() >= 1 and b.peer_count() >= 1)


def nothing_more(node, wait=0.4):
    time.sleep(wait)
    return node.received.empty()


# --- two nodes ---------------------------------------------------------------------

def test_connect_and_chat(make_node):
    a, b = make_node("alice"), make_node("bob")
    link(a, b)
    assert a.send_chat("hello bob") == 1
    sender_id, nickname, text = b.received.get(timeout=5)
    assert (sender_id, nickname, text) == (a.node_id, "alice", "hello bob")


def test_chat_works_in_both_directions(make_node):
    a, b = make_node("alice"), make_node("bob")
    link(a, b)
    a.send_chat("one")
    b.send_chat("two")
    assert a.received.get(timeout=5)[2] == "two"
    assert b.received.get(timeout=5)[2] == "one"


def test_sender_does_not_receive_its_own_message(make_node):
    a, b = make_node("alice"), make_node("bob")
    link(a, b)
    a.send_chat("hello")
    b.received.get(timeout=5)
    assert nothing_more(a)


def test_peers_see_each_other_in_the_peer_table(make_node):
    a, b = make_node(), make_node()
    link(a, b)
    assert [info[0] for info in a.peer_info()] == [b.node_id]
    assert [info[0] for info in b.peer_info()] == [a.node_id]


def test_send_with_no_peers_returns_zero(make_node):
    a = make_node()
    assert a.send_chat("anyone there?") == 0


def test_empty_and_oversized_messages_are_refused(make_node):
    a = make_node()
    with pytest.raises(ChatError):
        a.send_chat("")
    with pytest.raises(ChatError):
        a.send_chat("x" * (config.MAX_CHAT_TEXT + 1))


# --- forwarding ---------------------------------------------------------------------

def test_message_is_relayed_through_a_middle_node(make_node):
    a, b, c = make_node("a"), make_node("b"), make_node("c")
    link(a, b)
    link(c, b)
    a.send_chat("via b")
    assert c.received.get(timeout=5)[2] == "via b"
    assert b.received.get(timeout=5)[2] == "via b"


def test_ttl_limits_how_far_a_message_travels(make_node, monkeypatch):
    monkeypatch.setattr(config, "INITIAL_TTL", 2)
    n0, n1, n2, n3 = (make_node(f"n{i}") for i in range(4))
    link(n1, n0)
    link(n2, n1)
    link(n3, n2)
    n0.send_chat("short range")
    assert n1.received.get(timeout=5)[2] == "short range"   # 1 hop
    assert n2.received.get(timeout=5)[2] == "short range"   # 2 hops
    assert nothing_more(n3)                                  # 3 hops: out of range


def test_a_loop_does_not_deliver_duplicates(make_node):
    a, b, c = make_node("a"), make_node("b"), make_node("c")
    link(a, b)
    link(b, c)
    link(c, a)
    a.send_chat("once")
    assert b.received.get(timeout=5)[2] == "once"
    assert c.received.get(timeout=5)[2] == "once"
    assert nothing_more(b)
    assert nothing_more(c)
    assert nothing_more(a)


# --- who can connect -----------------------------------------------------------------

def test_wrong_password_cannot_connect(make_node):
    a = make_node("alice")
    intruder = make_node("eve", handshake_key=OTHER_HS_KEY, message_key=OTHER_MSG_KEY)
    with pytest.raises(HandshakeError):
        intruder.connect("127.0.0.1", a.port)
    assert a.peer_count() == 0
    assert intruder.peer_count() == 0


def test_cannot_connect_to_yourself(make_node):
    a = make_node()
    with pytest.raises(HandshakeError):
        a.connect("127.0.0.1", a.port)


def test_connect_to_nothing_raises_os_error(make_node):
    a = make_node()
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    free_port = probe.getsockname()[1]
    probe.close()   # nobody is listening there now
    with pytest.raises(OSError):
        a.connect("127.0.0.1", free_port)


def test_a_second_link_to_the_same_node_is_refused(make_node):
    a, b = make_node(), make_node()
    link(a, b)
    assert a.connect("127.0.0.1", b.port) is False
    time.sleep(0.2)
    assert a.peer_count() == 1
    assert b.peer_count() == 1


def test_both_sides_connecting_at_once_end_up_with_one_link(make_node):
    for _ in range(15):
        a, b = make_node("a"), make_node("b")

        def connect(node, other):
            try:
                node.connect("127.0.0.1", other.port)
            except (HandshakeError, OSError):
                pass   # one attempt may lose the race. The end state is what matters.

        threads = [
            threading.Thread(target=connect, args=(a, b)),
            threading.Thread(target=connect, args=(b, a)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert wait_until(lambda: a.peer_count() == 1 and b.peer_count() == 1)
        time.sleep(0.3)   # let the loser link finish closing
        assert a.peer_count() == 1
        assert b.peer_count() == 1
        a.send_chat("still works")   # and the surviving link is the same one on both sides
        assert b.received.get(timeout=5)[2] == "still works"


def test_peer_limit(make_node, monkeypatch):
    monkeypatch.setattr(config, "PEER_MAX", 1)
    a, b, c = make_node(), make_node(), make_node()
    link(b, a)
    with pytest.raises((HandshakeError, OSError)):
        c.connect("127.0.0.1", a.port)
    assert a.peer_count() == 1
    assert c.peer_count() == 0


# --- disconnects ----------------------------------------------------------------------

def test_stopping_a_node_removes_it_from_its_peers(make_node):
    a, b = make_node(), make_node()
    link(a, b)
    a.stop()
    assert wait_until(lambda: b.peer_count() == 0)


def test_reconnect_after_a_drop(make_node):
    a, b = make_node("a"), make_node("b")
    link(a, b)
    peer = a._peer_list()[0]
    peer.close()   # simulate the link dropping
    assert wait_until(lambda: a.peer_count() == 0 and b.peer_count() == 0)
    link(a, b)
    a.send_chat("back again")
    assert b.received.get(timeout=5)[2] == "back again"


# --- robustness ------------------------------------------------------------------------

def raw_connection(node):
    """A fake peer that knows the password but sends whatever we tell it to."""
    sock = socket.create_connection(("127.0.0.1", node.port))
    peer = Peer(sock, "raw", HS_KEY, ident(99), ConnType.MESH, Role.INITIATOR)
    peer.handshake()
    return peer


def chat_packet(key=MSG_KEY, text="valid"):
    return encrypt_packet(
        key,
        packet_type=PacketType.CHAT,
        ttl=5,
        message_id=new_message_id(),
        sender_id=ident(99),
        plaintext=encode_chat("raw", text),
    )


def test_node_survives_garbage_and_still_works(make_node):
    a = make_node()
    raw = raw_connection(a)
    assert wait_until(lambda: a.peer_count() == 1)

    raw.send(b"junk")                                   # not a packet at all
    raw.send_packet(chat_packet(key=OTHER_MSG_KEY))     # right format, wrong key
    raw.send_packet(chat_packet(text="valid"))          # a good one

    assert a.received.get(timeout=5)[1:] == ("raw", "valid")
    assert nothing_more(a)
    assert a.peer_count() == 1   # the bad packets did not drop the link
    raw.close()


def test_forged_copy_cannot_block_the_real_message(make_node):
    # A packet that fails authentication must NOT be remembered as "seen".
    a = make_node()
    raw = raw_connection(a)
    real = chat_packet(text="the real one")
    forged = real.__class__(
        type=real.type, ttl=real.ttl, message_id=real.message_id, sender_id=real.sender_id,
        nonce=real.nonce, payload=bytes([real.payload[0] ^ 1]) + real.payload[1:],
    )
    raw.send_packet(forged)   # same ID, tampered payload
    raw.send_packet(real)
    assert a.received.get(timeout=5)[2] == "the real one"
    raw.close()


def test_a_crashing_callback_does_not_stop_the_node(make_node):
    calls = []

    def bad_callback(sender_id, nickname, text):
        calls.append(text)
        raise RuntimeError("bug in the display code")

    a = Node(ident(50), HS_KEY, MSG_KEY, "a", bad_callback, host="127.0.0.1", port=0)
    a.start()
    try:
        raw = raw_connection(a)
        raw.send_packet(chat_packet(text="first"))
        raw.send_packet(chat_packet(text="second"))
        assert wait_until(lambda: calls == ["first", "second"])
        raw.close()
    finally:
        a.stop()