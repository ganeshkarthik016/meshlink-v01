"""Small network helpers."""

import socket


def local_ip() -> str:
    """Our address on the local network, so we can tell others where to reach us."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("10.255.255.255", 1))   # UDP connect sends nothing; it only picks a route
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"