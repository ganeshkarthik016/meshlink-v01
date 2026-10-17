import pytest

from p2pchat import config
from p2pchat.crypto import derive_keys

PASSWORD = "correct horse"
ROOM = "lab-room-1"


def test_returns_two_32_byte_keys():
    handshake_key, message_key = derive_keys(PASSWORD, ROOM)
    assert len(handshake_key) == 32
    assert len(message_key) == 32


def test_same_input_gives_same_keys():
    assert derive_keys(PASSWORD, ROOM) == derive_keys(PASSWORD, ROOM)


def test_the_two_keys_are_different():
    handshake_key, message_key = derive_keys(PASSWORD, ROOM)
    assert handshake_key != message_key


def test_different_password_gives_different_keys():
    assert derive_keys(PASSWORD, ROOM) != derive_keys("another password", ROOM)


def test_different_room_gives_different_keys():
    assert derive_keys(PASSWORD, ROOM) != derive_keys(PASSWORD, "other-room")


def test_short_password_is_rejected():
    with pytest.raises(ValueError):
        derive_keys("a" * (config.MIN_PASSWORD_LENGTH - 1), ROOM)


def test_password_of_minimum_length_is_accepted():
    handshake_key, _ = derive_keys("a" * config.MIN_PASSWORD_LENGTH, ROOM)
    assert len(handshake_key) == 32


def test_empty_room_id_is_rejected():
    with pytest.raises(ValueError):
        derive_keys(PASSWORD, "")


def test_non_ascii_password_works():
    handshake_key, message_key = derive_keys("pässwörd-ñ-日本語", ROOM)
    assert len(handshake_key) == 32
    assert len(message_key) == 32