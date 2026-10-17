"""Length-prefixed frames over a TCP socket.

TCP is a stream, not a list of messages: one recv() can return half a
message, or two messages stuck together. So every message is sent as a
"frame": a 4-byte length, then exactly that many bytes. The receiver reads
the length first, then reads exactly that much.

Timeouts are not handled here. If the socket has a timeout and nothing
arrives in time, the socket's own TimeoutError passes straight through.
"""

import socket
import struct

from p2pchat import config

_LENGTH = struct.Struct("!I")  # 4 bytes, big-endian, unsigned


class FrameError(ValueError):
    """A frame is too large, or its length makes no sense."""


class ConnectionClosed(ConnectionError):
    """The other side closed the connection."""


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes, however many recv() calls that takes."""
    chunks = []
    remaining = n
    while remaining > 0:
        data = sock.recv(remaining)
        if not data:  # b"" means the other side closed the connection
            raise ConnectionClosed("connection closed")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def send_frame(sock: socket.socket, data: bytes, max_size: int = config.MAX_FRAME_SIZE) -> None:
    """Send one frame: 4-byte length, then the data."""
    if len(data) > max_size:
        raise FrameError(f"frame of {len(data)} bytes exceeds the limit of {max_size}")
    sock.sendall(_LENGTH.pack(len(data)) + data)


def recv_frame(sock: socket.socket, max_size: int = config.MAX_FRAME_SIZE) -> bytes:
    """Receive one frame and return its data.

    The length is checked BEFORE reading the data, so a bad or hostile
    length cannot make us wait for (or allocate) gigabytes.
    """
    (length,) = _LENGTH.unpack(recv_exact(sock, _LENGTH.size))
    if length > max_size:
        raise FrameError(f"frame of {length} bytes exceeds the limit of {max_size}")
    return recv_exact(sock, length)