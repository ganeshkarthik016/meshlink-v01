"""The chat message format: nickname and text packed into a payload.

Pure functions, no network. node.py encrypts the payload this module builds.

Payload layout:  nickname length (1 byte) | nickname (UTF-8) | text (UTF-8)
"""

import unicodedata

from p2pchat import config


class ChatError(ValueError):
    """A chat message is empty, too long, or not valid."""


def sanitize(text: str) -> str:
    """Remove control characters (they can move the cursor or fake output
    in a terminal). Used on everything we send and everything we print."""
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cc")


def encode_chat(nickname: str, text: str) -> bytes:
    nickname = sanitize(nickname).strip()
    text = sanitize(text).strip()
    nick_bytes = nickname.encode()
    text_bytes = text.encode()
    if not 1 <= len(nick_bytes) <= config.MAX_NICKNAME_BYTES:
        raise ChatError(f"nickname must be 1 to {config.MAX_NICKNAME_BYTES} bytes")
    if not 1 <= len(text_bytes) <= config.MAX_CHAT_TEXT:
        raise ChatError(f"message must be 1 to {config.MAX_CHAT_TEXT} bytes")
    return bytes([len(nick_bytes)]) + nick_bytes + text_bytes


def decode_chat(payload: bytes) -> tuple[str, str]:
    """Return (nickname, text). Raises ChatError on anything wrong.

    Anything that came from the network is checked, even from a room member.
    """
    if len(payload) < 3:
        raise ChatError("payload too short")
    nick_length = payload[0]
    if not 1 <= nick_length <= config.MAX_NICKNAME_BYTES:
        raise ChatError("bad nickname length")
    text_start = 1 + nick_length
    text_bytes = payload[text_start:]
    if not 1 <= len(text_bytes) <= config.MAX_CHAT_TEXT:
        raise ChatError("bad text length")
    try:
        nickname = payload[1:text_start].decode()
        text = text_bytes.decode()
    except UnicodeDecodeError:
        raise ChatError("not valid UTF-8") from None
    nickname = sanitize(nickname).strip()
    text = sanitize(text).strip()
    if not nickname or not text:
        raise ChatError("empty after cleaning")
    return nickname, text