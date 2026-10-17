import socket

import pytest

from p2pchat import config
from p2pchat.discovery import (
    KIND_REPLY,
    KIND_REQUEST,
    TAG_SIZE,
    Discovery,
    DiscoveryError,
    decode_packet,
    encode_packet,
    room_tag,
)

ID_A = b"A" * config.SENDER_ID_SIZE
ID_B = b"B" * config.SENDER_ID_SIZE
ID_C = b"C" * config.SENDER_ID_SIZE
ID_D = b"D" * config.SENDER_ID_SIZE


# --- packet format -----------------------------------------------------------------------

def test_packet_roundtrip():
    tag = room_tag("lab")
    data = encode_packet(KIND_REQUEST, tag, ID_A, 50002)
    assert len(data) == 20
    assert decode_packet(data) == (KIND_REQUEST, tag, ID_A, 50002)


def test_room_tag_is_stable_and_room_specific():
    assert len(room_tag("lab")) == TAG_SIZE
    assert room_tag("lab") == room_tag("lab")
    assert room_tag("lab") != room_tag("other")


@pytest.mark.parametrize("data", [b"", b"x" * 19, b"x" * 21, b"hello world"])
def test_wrong_size_is_rejected(data):
    with pytest.raises(DiscoveryError):
        decode_packet(data)


def test_unsupported_version_is_rejected():
    data = bytearray(encode_packet(KIND_REQUEST, room_tag("lab"), ID_A, 1))
    data[0] = 99
    with pytest.raises(DiscoveryError):
        decode_packet(bytes(data))


def test_unknown_kind_is_rejected():
    data = bytearray(encode_packet(KIND_REQUEST, room_tag("lab"), ID_A, 1))
    data[1] = 77
    with pytest.raises(DiscoveryError):
        decode_packet(bytes(data))


def test_encode_rejects_bad_fields():
    with pytest.raises(DiscoveryError):
        encode_packet(9, room_tag("lab"), ID_A, 1)
    with pytest.raises(DiscoveryError):
        encode_packet(KIND_REQUEST, b"short", ID_A, 1)
    with pytest.raises(DiscoveryError):
        encode_packet(KIND_REQUEST, room_tag("lab"), b"short", 1)
    with pytest.raises(DiscoveryError):
        encode_packet(KIND_REQUEST, room_tag("lab"), ID_A, 70000)


# --- listening and searching ------------------------------------------------------------------

@pytest.fixture
def make_discovery():
    made = []

    def make(room="lab", node_id=ID_A, tcp_port=5000, can_accept=lambda: True):
        discovery = Discovery(room, node_id, lambda: tcp_port, can_accept, port=0)
        discovery.start()
        made.append(discovery)
        return discovery

    yield make
    for discovery in made:
        discovery.stop()


def aim_at(*discoveries):
    return [("127.0.0.1", d.port) for d in discoveries]


def test_finds_a_node_in_the_same_room(make_discovery):
    a = make_discovery(node_id=ID_A, tcp_port=5000)
    b = make_discovery(node_id=ID_B, tcp_port=6000)
    found = b.search(wait=0.5, targets=aim_at(a))
    assert [(c.host, c.port, c.node_id) for c in found] == [("127.0.0.1", 5000, ID_A)]


def test_a_different_room_stays_silent(make_discovery):
    a = make_discovery(room="lab", node_id=ID_A)
    b = make_discovery(room="other", node_id=ID_B)
    assert b.search(wait=0.5, targets=aim_at(a)) == []


def test_does_not_find_itself(make_discovery):
    # A broadcast loops back to the sender. Its own node ID must be ignored.
    a = make_discovery(node_id=ID_A)
    assert a.search(wait=0.5, targets=aim_at(a)) == []


def test_a_full_node_does_not_answer(make_discovery):
    a = make_discovery(node_id=ID_A, can_accept=lambda: False)
    b = make_discovery(node_id=ID_B)
    assert b.search(wait=0.5, targets=aim_at(a)) == []


def test_finds_several_nodes(make_discovery):
    a = make_discovery(node_id=ID_A, tcp_port=5001)
    b = make_discovery(node_id=ID_B, tcp_port=5002)
    c = make_discovery(node_id=ID_C, tcp_port=5003)
    searcher = make_discovery(node_id=ID_D)
    found = searcher.search(wait=0.7, targets=aim_at(a, b, c))
    assert {(f.node_id, f.port) for f in found} == {(ID_A, 5001), (ID_B, 5002), (ID_C, 5003)}


def test_the_same_node_is_listed_once(make_discovery):
    a = make_discovery(node_id=ID_A)
    b = make_discovery(node_id=ID_B)
    found = b.search(wait=0.5, targets=aim_at(a, a))   # asked twice, answered twice
    assert len(found) == 1


def test_no_answers_returns_an_empty_list(make_discovery):
    b = make_discovery(node_id=ID_B)
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()
    assert b.search(wait=0.3, targets=[("127.0.0.1", dead_port)]) == []


def test_garbage_does_not_break_the_listener(make_discovery):
    a = make_discovery(node_id=ID_A, tcp_port=5000)
    b = make_discovery(node_id=ID_B)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"", ("127.0.0.1", a.port))
        sock.sendto(b"hello there", ("127.0.0.1", a.port))
        sock.sendto(b"x" * 20, ("127.0.0.1", a.port))
        sock.sendto(b"y" * 600, ("127.0.0.1", a.port))
    found = b.search(wait=0.5, targets=aim_at(a))
    assert [c.node_id for c in found] == [ID_A]


def test_a_reply_is_not_treated_as_a_request(make_discovery):
    # Sending a REPLY packet to a listener must not trigger an answer.
    a = make_discovery(node_id=ID_A)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(0.4)
        sock.sendto(encode_packet(KIND_REPLY, room_tag("lab"), ID_B, 1234), ("127.0.0.1", a.port))
        with pytest.raises(TimeoutError):
            sock.recvfrom(512)


def test_stopped_node_no_longer_answers(make_discovery):
    a = make_discovery(node_id=ID_A)
    b = make_discovery(node_id=ID_B)
    port = a.port
    a.stop()
    assert b.search(wait=0.4, targets=[("127.0.0.1", port)]) == []


def test_the_port_can_be_reused_after_stop():
    first = Discovery("lab", ID_A, lambda: 1, lambda: True, port=0)
    first.start()
    port = first.port
    first.stop()
    second = Discovery("lab", ID_B, lambda: 1, lambda: True, port=port)
    second.start()
    second.stop()