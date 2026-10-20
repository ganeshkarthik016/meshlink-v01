"""File sharing, the parts that need no network: the file table, the
announcement format, file name cleaning, hashing.

A file's ID is the SHA-256 of its contents, so the same file has the same ID
on every machine whatever it is called.

Announcement payload (before encryption):
    file ID (32) | size (8) | uploader node ID (8) | uploader IPv4 (4) |
    file port (2) | name length (1) | name (UTF-8)
"""

import hashlib
import socket
import struct
import threading
from pathlib import Path
from typing import NamedTuple

from p2pchat import config
from p2pchat.chat import sanitize


class FileError(ValueError):
    """A file or an announcement is not acceptable."""


class FileEntry(NamedTuple):
    file_id: bytes     # SHA-256 of the file
    name: str          # already cleaned, safe to use as a file name
    size: int          # bytes
    uploader_id: bytes
    host: str          # where to download it from (IPv4)
    port: int          # the uploader's file port


# --- file names, sizes, hashing ----------------------------------------------------------------

def sanitize_filename(name: str) -> str:
    """Make a name safe to use as a file name. Raises FileError if nothing usable is left.

    Keeps only the last path component, so "../../x" becomes "x" and a file can
    never be written outside the download folder.
    """
    name = sanitize(name)                                  # no control characters
    name = name.replace("\\", "/").split("/")[-1]          # last path component only
    for character in '<>:"|?*':
        name = name.replace(character, "_")                # not allowed on Windows
    name = name.strip(" .")                                # no leading dots or edge spaces
    if not name:
        raise FileError("that is not a usable file name")
    if len(name.encode()) > config.MAX_FILE_NAME_BYTES:
        raise FileError(f"file name is longer than {config.MAX_FILE_NAME_BYTES} bytes")
    return name


def hash_file(path) -> tuple:
    """Return (SHA-256 digest, size in bytes) of a file."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
    return digest.digest(), size


def format_size(count: int) -> str:
    size = float(count)
    for unit in ("B", "KB", "MB"):
        if size < 1024:
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


# --- the announcement ------------------------------------------------------------------------------

_ANNOUNCE = struct.Struct(f"!32sQ{config.SENDER_ID_SIZE}s4sHB")


def _check_entry(entry: FileEntry) -> None:
    if len(entry.file_id) != 32:
        raise FileError("bad file ID")
    if not 1 <= entry.size <= config.MAX_FILE_SIZE:
        raise FileError("bad file size")
    if len(entry.uploader_id) != config.SENDER_ID_SIZE:
        raise FileError("bad uploader ID")
    if not 1 <= entry.port <= 65535:
        raise FileError("bad port")
    try:
        address = socket.inet_aton(entry.host)
    except OSError:
        raise FileError("bad address") from None
    if address == b"\x00\x00\x00\x00" or address[0] >= 224:   # not a usable unicast address
        raise FileError("bad address")


def encode_announce(entry: FileEntry) -> bytes:
    _check_entry(entry)
    name = entry.name.encode()
    if not 1 <= len(name) <= config.MAX_FILE_NAME_BYTES:
        raise FileError("bad file name length")
    return _ANNOUNCE.pack(
        entry.file_id, entry.size, entry.uploader_id,
        socket.inet_aton(entry.host), entry.port, len(name),
    ) + name


def decode_announce(payload: bytes) -> FileEntry:
    """Parse an announcement from the network. Raises FileError on anything wrong."""
    if len(payload) <= _ANNOUNCE.size:
        raise FileError("announcement too short")
    file_id, size, uploader_id, address, port, name_length = _ANNOUNCE.unpack_from(payload)
    name_bytes = payload[_ANNOUNCE.size:]
    if not 1 <= name_length <= config.MAX_FILE_NAME_BYTES or len(name_bytes) != name_length:
        raise FileError("bad file name length")
    try:
        name = sanitize_filename(name_bytes.decode())
    except UnicodeDecodeError:
        raise FileError("file name is not valid UTF-8") from None
    entry = FileEntry(file_id, name, size, uploader_id, socket.inet_ntoa(address), port)
    _check_entry(entry)
    return entry


# --- the table of announced files -------------------------------------------------------------------

class FileTable:
    """Files announced in the room, in the order we heard about them. In memory only."""

    def __init__(self):
        self._lock = threading.Lock()
        self._entries = {}   # file ID -> FileEntry. A dict keeps insertion order

    def add(self, entry: FileEntry) -> bool:
        """Returns True if it was new. A known file, or a full table, returns False."""
        with self._lock:
            if entry.file_id in self._entries or len(self._entries) >= config.FILE_TABLE_MAX:
                return False
            self._entries[entry.file_id] = entry
            return True

    def entries(self) -> list:
        with self._lock:
            return list(self._entries.values())

    def find(self, token: str) -> FileEntry:
        """Look a file up by its number in the list (1, 2, ...) or by the start of
        its hash (at least 4 characters). Raises LookupError with a readable message."""
        token = token.strip().lower()
        entries = self.entries()
        if not token:
            raise LookupError("usage: /get <number or hash>")
        if token.isdigit() and len(token) <= 3:
            number = int(token)
            if 1 <= number <= len(entries):
                return entries[number - 1]
            raise LookupError(f"there is no file number {number}. Use /files")
        if len(token) < 4 or any(c not in "0123456789abcdef" for c in token):
            raise LookupError("give the number from /files, or at least 4 characters of the hash")
        matches = [e for e in entries if e.file_id.hex().startswith(token)]
        if not matches:
            raise LookupError(f"no file starts with {token}")
        if len(matches) > 1:
            raise LookupError(f"{len(matches)} files start with {token}. Type more of the hash")
        return matches[0]