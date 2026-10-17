from dataclasses import replace

import pytest

from p2pchat import config
from p2pchat.crypto import (
    PROOF_SIZE,
    CryptoError,
    decrypt_packet,
    encrypt_packet,
    handshake_proof,
)
from p2pchat.packet import PacketError, PacketType

KEY = b"k" * 32
OTHER_KEY = b"o" * 32
MESSAGE_ID = b"\x01" * config.MESSAGE_ID_SIZE
SENDER_ID = b"\x02" * config.SENDER_ID_SIZE


def encrypt(plaintext=b"hello", key=KEY, **overrides):
    fields = dict(
        packet_type=PacketType.CHAT,
        ttl=5,
        message_id=MESSAGE_ID,
        sender_id=SENDER_ID,
        plaintext=plaintext,
    )
    fields.update(overrides)
    return encrypt_packet(key, **fields)


# --- packet encryption ------------------------------------------------------------

def test_roundtrip():
    assert decrypt_packet(KEY, encrypt(b"hello world")) == b"hello world"


def test_roundtrip_empty_plaintext():
    assert decrypt_packet(KEY, encrypt(b"")) == b""


def test_payload_is_not_the_plaintext():
    packet = encrypt(b"secret message")
    assert b"secret message" not in packet.encode()


def test_same_plaintext_encrypts_differently_each_time():
    assert encrypt(b"hi").payload != encrypt(b"hi").payload


def test_changing_ttl_does_not_break_decryption():
    # The whole reason TTL is outside the authenticated header: relays lower it.
    packet = encrypt()
    assert decrypt_packet(KEY, packet.with_ttl(1)) == b"hello"


def test_wrong_key_fails():
    with pytest.raises(CryptoError):
        decrypt_packet(OTHER_KEY, encrypt())


def test_changed_payload_fails():
    packet = encrypt()
    flipped = bytes([packet.payload[0] ^ 1]) + packet.payload[1:]
    with pytest.raises(CryptoError):
        decrypt_packet(KEY, replace(packet, payload=flipped))


def test_changed_message_id_fails():
    packet = encrypt()
    with pytest.raises(CryptoError):
        decrypt_packet(KEY, replace(packet, message_id=b"\x09" * config.MESSAGE_ID_SIZE))


def test_changed_sender_id_fails():
    packet = encrypt()
    with pytest.raises(CryptoError):
        decrypt_packet(KEY, replace(packet, sender_id=b"\x09" * config.SENDER_ID_SIZE))


def test_changed_type_fails():
    packet = encrypt()
    with pytest.raises(CryptoError):
        decrypt_packet(KEY, replace(packet, type=PacketType.FILE_ANNOUNCE))


def test_changed_nonce_fails():
    packet = encrypt()
    with pytest.raises(CryptoError):
        decrypt_packet(KEY, replace(packet, nonce=b"\x09" * config.NONCE_SIZE))


@pytest.mark.parametrize("length", [0, 1, 15])
def test_payload_shorter_than_the_tag_fails_cleanly(length):
    packet = replace(encrypt(), payload=b"x" * length)
    with pytest.raises(CryptoError):
        decrypt_packet(KEY, packet)


def test_plaintext_too_large_is_rejected():
    with pytest.raises(PacketError):
        encrypt(b"x" * config.MAX_PAYLOAD_SIZE)  # ciphertext is 16 bytes longer


# --- handshake proof -------------------------------------------------------------

NONCE_A = b"a" * config.HANDSHAKE_NONCE_SIZE
NONCE_B = b"b" * config.HANDSHAKE_NONCE_SIZE
ID_A = b"A" * config.SENDER_ID_SIZE
ID_B = b"B" * config.SENDER_ID_SIZE


def proof(key=KEY, **overrides):
    fields = dict(
        conn_type=1,
        role=1,
        initiator_nonce=NONCE_A,
        responder_nonce=NONCE_B,
        initiator_id=ID_A,
        responder_id=ID_B,
    )
    fields.update(overrides)
    return handshake_proof(key, **fields)


def test_proof_size():
    assert len(proof()) == PROOF_SIZE


def test_same_inputs_give_the_same_proof():
    assert proof() == proof()


@pytest.mark.parametrize(
    "change",
    [
        dict(conn_type=2),
        dict(role=2),
        dict(initiator_nonce=b"x" * config.HANDSHAKE_NONCE_SIZE),
        dict(responder_nonce=b"x" * config.HANDSHAKE_NONCE_SIZE),
        dict(initiator_id=b"x" * config.SENDER_ID_SIZE),
        dict(responder_id=b"x" * config.SENDER_ID_SIZE),
    ],
)
def test_any_changed_input_changes_the_proof(change):
    assert proof(**change) != proof()


def test_different_key_gives_a_different_proof():
    assert proof(key=OTHER_KEY) != proof()


def test_bad_sizes_are_rejected():
    with pytest.raises(ValueError):
        proof(initiator_nonce=b"short")
    with pytest.raises(ValueError):
        proof(responder_id=b"short")