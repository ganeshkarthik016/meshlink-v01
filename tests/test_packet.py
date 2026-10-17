import random

import pytest

from p2pchat import config
from p2pchat.packet import (
    HEADER_SIZE,
    Packet,
    PacketError,
    PacketType,
    new_message_id,
)


def make_packet(**overrides):
    fields = dict(
        type=PacketType.CHAT,
        ttl=5,
        message_id=b"\x01" * config.MESSAGE_ID_SIZE,
        sender_id=b"\x02" * config.SENDER_ID_SIZE,
        nonce=b"\x03" * config.NONCE_SIZE,
        payload=b"hello",
    )
    fields.update(overrides)
    return Packet(**fields)


# --- layout ---------------------------------------------------------------

def test_header_size_is_39():
    assert HEADER_SIZE == 39


def test_encoded_length_is_header_plus_payload():
    assert len(make_packet(payload=b"abc").encode()) == HEADER_SIZE + 3


# --- roundtrip ------------------------------------------------------------

def test_roundtrip():
    original = make_packet()
    assert Packet.decode(original.encode()) == original


def test_roundtrip_empty_payload():
    original = make_packet(payload=b"")
    assert Packet.decode(original.encode()) == original


def test_roundtrip_every_type():
    for packet_type in PacketType:
        original = make_packet(type=packet_type)
        assert Packet.decode(original.encode()).type == packet_type


# --- decoding bad input ---------------------------------------------------

@pytest.mark.parametrize("length", [0, 1, HEADER_SIZE - 1])
def test_decode_truncated(length):
    data = make_packet().encode()[:length]
    with pytest.raises(PacketError):
        Packet.decode(data)


def test_decode_unknown_version():
    data = bytearray(make_packet().encode())
    data[0] = 99
    with pytest.raises(PacketError):
        Packet.decode(bytes(data))


def test_decode_unknown_type():
    data = bytearray(make_packet().encode())
    data[1] = 200
    with pytest.raises(PacketError):
        Packet.decode(bytes(data))


def test_decode_oversized_payload():
    data = make_packet().encode()[:HEADER_SIZE] + b"x" * (config.MAX_PAYLOAD_SIZE + 1)
    with pytest.raises(PacketError):
        Packet.decode(data)


def test_decode_garbage_only_raises_packet_error():
    # Whatever the network sends, decode must return a Packet or raise
    # PacketError. Any other exception would crash a receiver thread.
    rng = random.Random(0)
    for _ in range(500):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 120)))
        try:
            Packet.decode(data)
        except PacketError:
            pass


# --- building bad packets -------------------------------------------------

@pytest.mark.parametrize("ttl", [-1, 256, 1.5, "5"])
def test_bad_ttl(ttl):
    with pytest.raises(PacketError):
        make_packet(ttl=ttl)


@pytest.mark.parametrize("field", ["message_id", "sender_id", "nonce"])
def test_wrong_length_fields(field):
    with pytest.raises(PacketError):
        make_packet(**{field: b"short"})


def test_type_must_be_packet_type():
    with pytest.raises(PacketError):
        make_packet(type=1)


def test_payload_too_large():
    with pytest.raises(PacketError):
        make_packet(payload=b"x" * (config.MAX_PAYLOAD_SIZE + 1))


# --- aad: what gets authenticated -----------------------------------------

def test_aad_ignores_ttl():
    packet = make_packet(ttl=5)
    assert packet.aad() == packet.with_ttl(1).aad()


def test_aad_changes_with_type_id_and_sender():
    base = make_packet().aad()
    assert make_packet(type=PacketType.FILE_ANNOUNCE).aad() != base
    assert make_packet(message_id=b"\x09" * config.MESSAGE_ID_SIZE).aad() != base
    assert make_packet(sender_id=b"\x09" * config.SENDER_ID_SIZE).aad() != base


# --- ttl and forwarding ---------------------------------------------------

def test_with_ttl_changes_only_ttl():
    packet = make_packet(ttl=5)
    other = packet.with_ttl(2)
    assert other.ttl == 2
    assert packet.ttl == 5  # the original is untouched
    assert other.message_id == packet.message_id
    assert other.payload == packet.payload


def test_forwarded_lowers_ttl_by_one():
    assert make_packet(ttl=5).forwarded().ttl == 4
    assert make_packet(ttl=2).forwarded().ttl == 1


def test_ttl_1_is_not_forwarded():
    assert make_packet(ttl=1).forwarded() is None


def test_ttl_0_is_not_forwarded():
    assert make_packet(ttl=0).forwarded() is None


def test_packet_sent_with_ttl_n_reaches_n_hops():
    # The node that creates the packet sends it with TTL 5. Count how many
    # nodes receive it before it stops being forwarded.
    packet = make_packet(ttl=config.INITIAL_TTL)
    hops = 0
    while packet is not None:
        hops += 1  # one more node received it
        packet = packet.forwarded()
    assert hops == config.INITIAL_TTL


# --- message IDs ----------------------------------------------------------

def test_new_message_id_size_and_variety():
    ids = {new_message_id() for _ in range(100)}
    assert all(len(i) == config.MESSAGE_ID_SIZE for i in ids)
    assert len(ids) == 100