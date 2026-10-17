import socket
import struct
import threading

import pytest

from p2pchat import config
from p2pchat.framing import (
    ConnectionClosed,
    FrameError,
    recv_exact,
    recv_frame,
    send_frame,
)


@pytest.fixture
def pair():
    """Two connected sockets: whatever one sends, the other receives."""
    a, b = socket.socketpair()
    a.settimeout(5)
    b.settimeout(5)
    yield a, b
    a.close()
    b.close()


def run_in_thread(function):
    thread = threading.Thread(target=function, daemon=True)
    thread.start()
    return thread


# --- normal use -----------------------------------------------------------

def test_roundtrip(pair):
    a, b = pair
    send_frame(a, b"hello")
    assert recv_frame(b) == b"hello"


def test_empty_frame(pair):
    a, b = pair
    send_frame(a, b"")
    assert recv_frame(b) == b""


def test_frames_keep_their_boundaries(pair):
    a, b = pair
    send_frame(a, b"one")
    send_frame(a, b"two")
    send_frame(a, b"three")
    assert [recv_frame(b), recv_frame(b), recv_frame(b)] == [b"one", b"two", b"three"]


def test_largest_allowed_frame(pair):
    a, b = pair
    data = b"x" * config.MAX_FRAME_SIZE
    thread = run_in_thread(lambda: send_frame(a, data))  # big: send while we read
    assert recv_frame(b) == data
    thread.join(timeout=5)


# --- TCP delivers data in pieces ------------------------------------------

def test_frame_arriving_one_byte_at_a_time(pair):
    a, b = pair
    wire = struct.pack("!I", 5) + b"hello"

    def dribble():
        for i in range(len(wire)):
            a.sendall(wire[i : i + 1])

    thread = run_in_thread(dribble)
    assert recv_frame(b) == b"hello"
    thread.join(timeout=5)


def test_recv_exact_reads_exactly_n(pair):
    a, b = pair
    a.sendall(b"abcdefgh")
    assert recv_exact(b, 3) == b"abc"
    assert recv_exact(b, 5) == b"defgh"


# --- the other side closes ------------------------------------------------

def test_closed_before_any_data(pair):
    a, b = pair
    a.close()
    with pytest.raises(ConnectionClosed):
        recv_frame(b)


def test_closed_in_the_middle_of_a_frame(pair):
    a, b = pair
    a.sendall(struct.pack("!I", 10) + b"abc")  # promises 10 bytes, sends 3
    a.close()
    with pytest.raises(ConnectionClosed):
        recv_frame(b)


# --- bad or hostile input -------------------------------------------------

def test_oversized_length_is_rejected_without_reading_the_data(pair):
    a, b = pair
    a.sendall(struct.pack("!I", 4_000_000_000))  # claims a 4 GB frame
    with pytest.raises(FrameError):
        recv_frame(b)


def test_send_rejects_oversized_data(pair):
    a, _ = pair
    with pytest.raises(FrameError):
        send_frame(a, b"x" * (config.MAX_FRAME_SIZE + 1))


def test_custom_max_size(pair):
    a, b = pair
    send_frame(a, b"12345")
    with pytest.raises(FrameError):
        recv_frame(b, max_size=4)


# --- timeouts -------------------------------------------------------------

def test_timeout_passes_through(pair):
    _, b = pair
    b.settimeout(0.1)
    with pytest.raises(TimeoutError):
        recv_frame(b)