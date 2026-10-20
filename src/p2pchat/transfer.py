"""File sharing over the network: a small server for the files we shared, and
a chunked, resumable download.

Protocol on a FILE connection (after the handshake, framed like everything else):
  request:   type (1) | file ID (32) | offset (8) | length (4)     (45 bytes)
  response:  status (1) | data (only when status is OK)

The downloader asks for one chunk at a time (64 KB), starting at the size of
its partial file, so an interrupted download resumes where it stopped. When all
bytes are in, the whole file is hashed and must match the announced file ID.
"""

import logging
import os
import socket
import struct
import threading
from pathlib import Path
from typing import NamedTuple

from p2pchat import config
from p2pchat.files import FileEntry, FileError, FileTable, format_size, hash_file, sanitize_filename
from p2pchat.framing import FrameError
from p2pchat.netutil import local_ip
from p2pchat.peer import ConnType, HandshakeError, Peer, Role

log = logging.getLogger(__name__)

REQ_GET = 1

STATUS_OK = 0
STATUS_NOT_FOUND = 1      # we do not share that file
STATUS_BAD_REQUEST = 2    # malformed, or asks for bytes outside the file
STATUS_UNAVAILABLE = 3    # we shared it, but our copy is gone or has changed

_REQUEST = struct.Struct("!B32sQI")

_STATUS_TEXT = {
    STATUS_NOT_FOUND: "the uploader is not sharing that file any more",
    STATUS_BAD_REQUEST: "the uploader rejected the request",
    STATUS_UNAVAILABLE: "the uploader's copy of the file is missing or has changed",
}


class DownloadError(Exception):
    """A download could not be completed (the reason is in the message)."""


class SharedFile(NamedTuple):
    path: Path
    size: int


class FileService:
    def __init__(self, node_id, handshake_key, host, port, download_dir, advertise_host=None):
        """host/port: where our file server listens (port 0 = any free port).
        advertise_host: the address we tell others to download from
        (default: our address on the local network)."""
        self.table = FileTable()
        self.port = port
        self._node_id = node_id
        self._handshake_key = handshake_key
        self._host = host
        self._download_dir = Path(download_dir)
        self._advertise_host = advertise_host
        self._lock = threading.Lock()
        self._shared = {}          # file ID -> SharedFile
        self._active = set()       # file IDs being downloaded right now
        self._serving = set()      # Peers we are currently serving
        self._connections = 0
        self._server = None
        self._running = False

    # --- the server ---------------------------------------------------------------------------

    def start(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self._host, self.port))
            server.listen()
        except OSError:
            server.close()
            raise
        self._server = server
        self.port = server.getsockname()[1]
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self) -> None:
        self._running = False
        if self._server is not None:
            try:
                self._server.shutdown(socket.SHUT_RDWR)   # wakes up accept()
            except OSError:
                pass
            self._server.close()
        with self._lock:
            serving = list(self._serving)
        for peer in serving:
            peer.close()

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, address = self._server.accept()
            except OSError:
                break
            with self._lock:
                full = self._connections >= config.FILE_MAX_CONNECTIONS
                if not full:
                    self._connections += 1
            if full:
                conn.close()
                continue
            threading.Thread(target=self._serve, args=(conn, address), daemon=True).start()

    def _serve(self, conn, address) -> None:
        peer = None
        try:
            peer = Peer(conn, address, self._handshake_key, self._node_id, ConnType.FILE, Role.RESPONDER)
            peer.handshake()
            peer.set_timeout(config.CHUNK_TIMEOUT)   # drop connections that go quiet
            with self._lock:
                self._serving.add(peer)
            while True:
                peer.send(self._answer(peer.recv()))
        except HandshakeError as error:
            log.info("file handshake with %s failed: %s", address, error)
        except (OSError, FrameError):
            pass   # the downloader finished, went away, or sent a bad frame
        finally:
            if peer is not None:
                with self._lock:
                    self._serving.discard(peer)
                peer.close()
            else:
                conn.close()
            with self._lock:
                self._connections -= 1

    def _answer(self, request: bytes) -> bytes:
        """The reply to one request. Never raises: a bad request gets a status."""
        if len(request) != _REQUEST.size:
            return bytes([STATUS_BAD_REQUEST])
        kind, file_id, offset, length = _REQUEST.unpack(request)
        if kind != REQ_GET or not 1 <= length <= config.CHUNK_SIZE:
            return bytes([STATUS_BAD_REQUEST])
        with self._lock:
            shared = self._shared.get(file_id)
        if shared is None:
            return bytes([STATUS_NOT_FOUND])
        if offset + length > shared.size:
            return bytes([STATUS_BAD_REQUEST])
        try:
            if shared.path.stat().st_size != shared.size:   # changed since we shared it
                return bytes([STATUS_UNAVAILABLE])
            with open(shared.path, "rb") as handle:
                handle.seek(offset)
                data = handle.read(length)
        except OSError:
            return bytes([STATUS_UNAVAILABLE])
        if len(data) != length:
            return bytes([STATUS_UNAVAILABLE])
        return bytes([STATUS_OK]) + data

    # --- sharing ----------------------------------------------------------------------------------

    def share(self, path) -> FileEntry:
        """Hash a file and start serving it. Raises FileError if it is not acceptable."""
        path = Path(path).expanduser()
        if not path.is_file():
            raise FileError(f"{path} is not a file")
        size = path.stat().st_size
        if size == 0:
            raise FileError("that file is empty")
        if size > config.MAX_FILE_SIZE:
            raise FileError(f"that file is larger than the {format_size(config.MAX_FILE_SIZE)} limit")
        name = sanitize_filename(path.name)
        file_id, hashed_size = hash_file(path)
        if hashed_size != size:
            raise FileError("the file changed while it was being read")
        entry = FileEntry(file_id, name, size, self._node_id, self._advertise_host or local_ip(), self.port)
        with self._lock:
            self._shared[file_id] = SharedFile(path.resolve(), size)
        self.table.add(entry)
        return entry

    # --- downloading -------------------------------------------------------------------------------

    def download(self, entry: FileEntry, progress=None) -> Path:
        """Download a file from its uploader. Returns the path of the finished file.

        progress(received, total) is called after every chunk. If the download is
        interrupted, the partial file is kept and calling download again resumes it.

        Raises DownloadError (the reason is in the message), HandshakeError
        (wrong password, or not a node) or OSError (cannot reach the uploader).
        """
        with self._lock:
            if entry.file_id in self._active:
                raise DownloadError("you are already downloading that file")
            self._active.add(entry.file_id)
        try:
            return self._download(entry, progress)
        finally:
            with self._lock:
                self._active.discard(entry.file_id)

    def _download(self, entry: FileEntry, progress) -> Path:
        # Defence in depth: never trust a name, even one that was cleaned before.
        try:
            name = sanitize_filename(entry.name)
        except FileError as error:
            raise DownloadError(str(error)) from None
        self._download_dir.mkdir(parents=True, exist_ok=True)
        partial = self._download_dir / f"{name}.{entry.file_id.hex()[:8]}.part"

        received = partial.stat().st_size if partial.exists() else 0
        if received > entry.size:   # not a partial copy of this file: start again
            partial.unlink()
            received = 0

        if received < entry.size:
            self._fetch(entry, partial, received, progress)

        digest, size = hash_file(partial)
        if size != entry.size or digest != entry.file_id:
            partial.unlink()   # keeping it would make every retry fail the same way
            raise DownloadError("the downloaded file does not match its hash: it is corrupted or not the announced file. Try /get again")
        final = self._unique_path(name)
        os.replace(partial, final)
        return final

    def _fetch(self, entry: FileEntry, partial: Path, received: int, progress) -> None:
        sock = socket.create_connection((entry.host, entry.port), timeout=config.HANDSHAKE_TIMEOUT)
        try:
            peer = Peer(sock, (entry.host, entry.port), self._handshake_key, self._node_id,
                        ConnType.FILE, Role.INITIATOR)
        except OSError:
            sock.close()
            raise
        peer.handshake()   # raises HandshakeError, and closes the connection itself
        peer.set_timeout(config.CHUNK_TIMEOUT)
        try:
            with open(partial, "ab") as out:
                while received < entry.size:
                    length = min(config.CHUNK_SIZE, entry.size - received)
                    peer.send(_REQUEST.pack(REQ_GET, entry.file_id, received, length))
                    reply = peer.recv()
                    status = reply[0] if reply else STATUS_BAD_REQUEST
                    if status != STATUS_OK:
                        raise DownloadError(_STATUS_TEXT.get(status, "the uploader sent an unexpected reply"))
                    data = reply[1:]
                    if len(data) != length:
                        raise DownloadError("the uploader sent the wrong amount of data")
                    out.write(data)
                    received += length
                    if progress is not None:
                        progress(received, entry.size)
        except FrameError as error:
            raise DownloadError(f"bad data from the uploader: {error}") from None
        finally:
            peer.close()

    def _unique_path(self, name: str) -> Path:
        """download_dir/name, or name (1).ext, name (2).ext ... if it already exists."""
        candidate = self._download_dir / name
        stem, extension = os.path.splitext(name)
        number = 0
        while candidate.exists():
            number += 1
            candidate = self._download_dir / f"{stem} ({number}){extension}"
        return candidate