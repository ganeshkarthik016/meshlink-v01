import pytest

from p2pchat import config
from p2pchat.chat import ChatError, decode_chat, encode_chat, sanitize


def test_roundtrip():
    assert decode_chat(encode_chat("ganesh", "hello there")) == ("ganesh", "hello there")


def test_unicode_roundtrip():
    assert decode_chat(encode_chat("गणेश", "héllo 日本語 🙂")) == ("गणेश", "héllo 日本語 🙂")


def test_sanitize_removes_control_characters():
    assert sanitize("a\x1b[31mb\x00c\nd") == "a[31mbcd"


def test_encode_cleans_the_text():
    assert decode_chat(encode_chat("bob", "hi\x1b[2J there")) == ("bob", "hi[2J there")


def test_empty_text_rejected():
    with pytest.raises(ChatError):
        encode_chat("bob", "")
    with pytest.raises(ChatError):
        encode_chat("bob", "   \x1b ")


def test_empty_nickname_rejected():
    with pytest.raises(ChatError):
        encode_chat("", "hello")


def test_nickname_too_long():
    with pytest.raises(ChatError):
        encode_chat("n" * (config.MAX_NICKNAME_BYTES + 1), "hello")


def test_nickname_at_the_limit():
    assert decode_chat(encode_chat("n" * config.MAX_NICKNAME_BYTES, "hi"))[0] == "n" * config.MAX_NICKNAME_BYTES


def test_text_too_long():
    with pytest.raises(ChatError):
        encode_chat("bob", "x" * (config.MAX_CHAT_TEXT + 1))


def test_text_at_the_limit():
    assert decode_chat(encode_chat("bob", "x" * config.MAX_CHAT_TEXT))[1] == "x" * config.MAX_CHAT_TEXT


def test_chat_error_is_a_value_error():
    with pytest.raises(ValueError):
        encode_chat("bob", "")


# --- decoding hostile or broken payloads -----------------------------------------------

@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x00",
        b"\x05ab",                                  # nickname length longer than the data
        b"\x00hello",                               # zero-length nickname
        b"\x03bob",                                 # no text at all
        bytes([config.MAX_NICKNAME_BYTES + 1]) + b"n" * 40 + b"hi",
        b"\x03bob\xff\xfe",                         # text is not UTF-8
        b"\x03\xff\xfe\xfdhi",                      # nickname is not UTF-8
        b"\x03bob\x1b\x1b",                         # nothing left after cleaning
    ],
)
def test_bad_payloads_raise_chat_error(payload):
    with pytest.raises(ChatError):
        decode_chat(payload)


def test_oversized_text_in_payload():
    with pytest.raises(ChatError):
        decode_chat(b"\x03bob" + b"x" * (config.MAX_CHAT_TEXT + 1))


def test_decode_cleans_control_characters():
    payload = b"\x03bob" + b"hi\x1b[31m there"
    assert decode_chat(payload) == ("bob", "hi[31m there")