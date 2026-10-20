import hashlib
import random
import socket
import threading
import time

import pytest

from p2pchat import config
from p2pchat.files import FileEntry, FileError
from p2pchat.framing import send_frame
from p2pchat.peer import ConnType, HandshakeError, Peer, Role
from p2pchat.transfer import (
    REQ_GET,
    STATUS_BAD_REQUEST,
    STATUS_NOT_FOUND,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    DownloadError,
    FileService,
    _REQUEST,
)

HS_KEY = b"h" * 32
OTHER_KEY = b"x" * 32
CHUNK = config.CHUNK_SIZE


def wait_until(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


@pytest.fixture
def make_service(tmp_path):
    services = []

    def make(name, key=HS_KEY, node_byte=1):
        service = FileService(
            bytes([node_byte]) * config.SENDER_ID_SIZE, key, "127.0.0.1", 0,
            tmp_path / name, advertise_host="127.0.0.1",
        )
        service.start()
        services.append(service)
        service.dir = tmp_path / name
        return service

    yield make
    for service in services:
        service.stop()


def make_file(directory, name, size, seed=0):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(random.Random(seed).randbytes(size))
    return path


@pytest.fixture
def pair(make_service, tmp_path):
    """An uploader and a downloader that share the room key."""
    return make_service("up", node_byte=1), make_service("down", node_byte=2)


# --- normal downloads -------------------------------------------------------------------------------

@pytest.mark.parametrize("size", [1, 100, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 100])
def test_download_roundtrip(pair, tmp_path, size):
    up, down = pair
    source = make_file(tmp_path / "src", "data.bin", size, seed=size)
    entry, = [up.share(source)]
    result = down.download(entry)
    assert result == down.dir / "data.bin"
    assert result.read_bytes() == source.read_bytes()
    assert hashlib.sha256(result.read_bytes()).digest() == entry.file_id


def test_progress_reports_every_chunk(pair, tmp_path):
    up, down = pair
    source = make_file(tmp_path / "src", "data.bin", 3 * CHUNK + 100)
    reports = []
    down.download(up.share(source), progress=lambda done, total: reports.append((done, total)))
    assert [done for done, _ in reports] == [CHUNK, 2 * CHUNK, 3 * CHUNK, 3 * CHUNK + 100]
    assert {total for _, total in reports} == {3 * CHUNK + 100}


def test_no_partial_file_is_left_behind(pair, tmp_path):
    up, down = pair
    down.download(up.share(make_file(tmp_path / "src", "data.bin", 1000)))
    assert [p.name for p in down.dir.iterdir()] == ["data.bin"]


def test_existing_names_are_not_overwritten(pair, tmp_path):
    up, down = pair
    entry = up.share(make_file(tmp_path / "src", "report.pdf", 500))
    first = down.download(entry)
    second = down.download(entry)
    third = down.download(entry)
    assert [p.name for p in (first, second, third)] == ["report.pdf", "report (1).pdf", "report (2).pdf"]


def test_the_download_folder_is_created(pair, tmp_path):
    up, down = pair
    assert not down.dir.exists()
    down.download(up.share(make_file(tmp_path / "src", "a.txt", 10)))
    assert down.dir.is_dir()


def test_several_downloads_at_once(make_service, tmp_path):
    up = make_service("up", node_byte=1)
    entries = [up.share(make_file(tmp_path / "src", f"f{i}.bin", 2 * CHUNK + i, seed=i)) for i in range(4)]
    downloaders = [make_service(f"d{i}", node_byte=10 + i) for i in range(4)]
    results = {}

    def run(index):
        results[index] = downloaders[index].download(entries[index]).read_bytes()

    threads = [threading.Thread(target=run, args=(i,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    for i in range(4):
        assert hashlib.sha256(results[i]).digest() == entries[i].file_id


# --- resuming -------------------------------------------------------------------------------------------

def partial_path(service, entry):
    service.dir.mkdir(parents=True, exist_ok=True)
    return service.dir / f"{entry.name}.{entry.file_id.hex()[:8]}.part"


def test_resumes_from_a_partial_file(pair, tmp_path):
    up, down = pair
    source = make_file(tmp_path / "src", "data.bin", 3 * CHUNK + 100)
    entry = up.share(source)
    content = source.read_bytes()
    partial_path(down, entry).write_bytes(content[:100_000])

    reports = []
    result = down.download(entry, progress=lambda done, total: reports.append(done))
    assert reports[0] == 100_000 + CHUNK        # it asked only for what was missing
    assert result.read_bytes() == content


def test_a_complete_partial_file_needs_no_connection(pair, tmp_path):
    up, down = pair
    source = make_file(tmp_path / "src", "data.bin", 5000)
    entry = up.share(source)
    partial_path(down, entry).write_bytes(source.read_bytes())
    up.stop()   # the uploader is gone, and that is fine
    assert down.download(entry).read_bytes() == source.read_bytes()


def test_a_wrong_partial_file_fails_the_hash_check_and_is_deleted(pair, tmp_path):
    up, down = pair
    source = make_file(tmp_path / "src", "data.bin", 2 * CHUNK)
    entry = up.share(source)
    partial_path(down, entry).write_bytes(b"\x00" * 1000)   # right size to resume, wrong content
    with pytest.raises(DownloadError, match="hash"):
        down.download(entry)
    assert list(down.dir.iterdir()) == []
    assert down.download(entry).read_bytes() == source.read_bytes()   # a retry starts clean


def test_a_partial_file_bigger_than_the_file_starts_again(pair, tmp_path):
    up, down = pair
    source = make_file(tmp_path / "src", "data.bin", 1000)
    entry = up.share(source)
    partial_path(down, entry).write_bytes(b"x" * 5000)
    assert down.download(entry).read_bytes() == source.read_bytes()


# --- things going wrong ----------------------------------------------------------------------------------

def test_wrong_password(make_service, tmp_path):
    up = make_service("up", node_byte=1)
    intruder = make_service("intruder", key=OTHER_KEY, node_byte=2)
    entry = up.share(make_file(tmp_path / "src", "data.bin", 100))
    with pytest.raises(HandshakeError):
        intruder.download(entry)
    assert not intruder.dir.exists() or list(intruder.dir.iterdir()) == []


def test_uploader_not_running(pair, tmp_path):
    up, down = pair
    entry = up.share(make_file(tmp_path / "src", "data.bin", 100))
    up.stop()
    with pytest.raises(OSError):
        down.download(entry)


def test_the_uploader_deleted_the_file(pair, tmp_path):
    up, down = pair
    source = make_file(tmp_path / "src", "data.bin", 2 * CHUNK)
    entry = up.share(source)
    source.unlink()
    with pytest.raises(DownloadError, match="missing or has changed"):
        down.download(entry)


def test_the_uploader_changed_the_file(pair, tmp_path):
    up, down = pair
    source = make_file(tmp_path / "src", "data.bin", 2 * CHUNK)
    entry = up.share(source)
    source.write_bytes(b"something else entirely")
    with pytest.raises(DownloadError, match="missing or has changed"):
        down.download(entry)


def test_the_uploader_does_not_share_that_file(pair, tmp_path):
    up, down = pair
    entry = up.share(make_file(tmp_path / "src", "data.bin", 100))
    unknown = entry._replace(file_id=b"\x77" * 32)
    with pytest.raises(DownloadError, match="not sharing"):
        down.download(unknown)


def test_an_announced_size_that_does_not_match_the_file(pair, tmp_path):
    up, down = pair
    entry = up.share(make_file(tmp_path / "src", "data.bin", 1000))
    with pytest.raises(DownloadError):
        down.download(entry._replace(size=5000))   # asks for bytes the file does not have


def test_one_download_per_file_at_a_time(pair, tmp_path):
    up, down = pair
    entry = up.share(make_file(tmp_path / "src", "data.bin", 100))
    down._active.add(entry.file_id)   # pretend a download of it is running
    with pytest.raises(DownloadError, match="already downloading"):
        down.download(entry)


def test_the_slot_is_freed_after_a_failure(pair, tmp_path):
    up, down = pair
    entry = up.share(make_file(tmp_path / "src", "data.bin", 100))
    bad = entry._replace(file_id=b"\x77" * 32)
    with pytest.raises(DownloadError):
        down.download(bad)
    assert bad.file_id not in down._active


def test_a_dangerous_name_cannot_escape_the_download_folder(pair, tmp_path):
    up, down = pair
    entry = up.share(make_file(tmp_path / "src", "data.bin", 100))
    evil = entry._replace(name="../../evil.txt")
    result = down.download(evil)
    assert result.parent == down.dir
    assert result.name == "evil.txt"
    assert not (tmp_path / "evil.txt").exists()


def test_an_unusable_name_is_refused(pair, tmp_path):
    up, down = pair
    entry = up.share(make_file(tmp_path / "src", "data.bin", 100))
    with pytest.raises(DownloadError):
        down.download(entry._replace(name=".."))


# --- what can be shared ------------------------------------------------------------------------------------

def test_share_errors(make_service, tmp_path):
    up = make_service("up")
    with pytest.raises(FileError, match="not a file"):
        up.share(tmp_path / "does-not-exist")
    with pytest.raises(FileError, match="not a file"):
        up.share(tmp_path)   # a folder
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    with pytest.raises(FileError, match="empty"):
        up.share(empty)
    long_name = make_file(tmp_path, "n" * (config.MAX_FILE_NAME_BYTES + 1), 10)
    with pytest.raises(FileError, match="longer"):
        up.share(long_name)


def test_share_size_limit(make_service, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MAX_FILE_SIZE", 1000)
    up = make_service("up")
    with pytest.raises(FileError, match="larger"):
        up.share(make_file(tmp_path, "big.bin", 1001))
    assert up.share(make_file(tmp_path, "ok.bin", 1000)).size == 1000


def test_share_adds_the_file_to_our_own_table_once(make_service, tmp_path):
    up = make_service("up")
    source = make_file(tmp_path, "a.txt", 50)
    first = up.share(source)
    up.share(source)
    assert up.table.entries() == [first]


def test_share_entry_has_our_address_and_the_content_hash(make_service, tmp_path):
    up = make_service("up", node_byte=7)
    source = make_file(tmp_path, "a.txt", 50)
    entry = up.share(source)
    assert entry.host == "127.0.0.1"
    assert entry.port == up.port
    assert entry.uploader_id == bytes([7]) * config.SENDER_ID_SIZE
    assert entry.file_id == hashlib.sha256(source.read_bytes()).digest()
    assert entry.name == "a.txt"


def test_the_same_content_under_another_name_has_the_same_id(make_service, tmp_path):
    up = make_service("up")
    a = make_file(tmp_path, "one.txt", 50, seed=5)
    b = tmp_path / "two.txt"
    b.write_bytes(a.read_bytes())
    assert up.share(a).file_id == up.share(b).file_id


# --- the server on its own: bad requests ------------------------------------------------------------------------

def raw_client(service):
    sock = socket.create_connection(("127.0.0.1", service.port))
    peer = Peer(sock, "raw", HS_KEY, b"\x63" * config.SENDER_ID_SIZE, ConnType.FILE, Role.INITIATOR)
    peer.handshake()
    return peer


def ask(peer, file_id, offset, length, kind=REQ_GET):
    peer.send(_REQUEST.pack(kind, file_id, offset, length))
    return peer.recv()


def test_server_answers_with_statuses(make_service, tmp_path):
    up = make_service("up")
    source = make_file(tmp_path, "a.bin", 1000)
    entry = up.share(source)
    peer = raw_client(up)
    try:
        reply = ask(peer, entry.file_id, 100, 50)
        assert reply[0] == STATUS_OK and reply[1:] == source.read_bytes()[100:150]
        assert ask(peer, b"\x77" * 32, 0, 10) == bytes([STATUS_NOT_FOUND])
        assert ask(peer, entry.file_id, 990, 20) == bytes([STATUS_BAD_REQUEST])            # past the end
        assert ask(peer, entry.file_id, 0, 0) == bytes([STATUS_BAD_REQUEST])               # nothing asked for
        assert ask(peer, entry.file_id, 0, CHUNK + 1) == bytes([STATUS_BAD_REQUEST])       # bigger than a chunk
        assert ask(peer, entry.file_id, 0, 10, kind=9) == bytes([STATUS_BAD_REQUEST])      # unknown request type
        peer.send(b"not a request")
        assert peer.recv() == bytes([STATUS_BAD_REQUEST])
        reply = ask(peer, entry.file_id, 0, 10)                                             # still usable
        assert reply[0] == STATUS_OK
        source.unlink()
        assert ask(peer, entry.file_id, 0, 10) == bytes([STATUS_UNAVAILABLE])
    finally:
        peer.close()


def test_server_survives_a_client_that_vanishes(make_service, tmp_path):
    up = make_service("up")
    down = make_service("down", node_byte=2)
    entry = up.share(make_file(tmp_path, "a.bin", 2 * CHUNK))
    peer = raw_client(up)
    peer.send(_REQUEST.pack(REQ_GET, entry.file_id, 0, CHUNK))
    peer.close()   # goes away without reading the answer
    assert down.download(entry).stat().st_size == 2 * CHUNK


def test_oversized_frame_from_a_client_closes_the_connection(make_service, tmp_path):
    up = make_service("up")
    entry = up.share(make_file(tmp_path, "a.bin", 100))
    peer = raw_client(up)
    send_frame(peer._sock, b"x" * config.MAX_FRAME_SIZE)   # allowed size, but not a request
    assert peer.recv() == bytes([STATUS_BAD_REQUEST])
    peer.close()


def test_connection_limit(make_service, monkeypatch):
    monkeypatch.setattr(config, "FILE_MAX_CONNECTIONS", 1)
    up = make_service("up")
    first = raw_client(up)   # holds the only slot
    try:
        with pytest.raises(HandshakeError):
            raw_client(up)
    finally:
        first.close()
    assert wait_until(lambda: up._connections == 0)
    raw_client(up).close()   # the slot is free again


def test_a_failed_handshake_frees_its_slot(make_service):
    up = make_service("up")
    sock = socket.create_connection(("127.0.0.1", up.port))
    send_frame(sock, b"garbage")
    sock.close()
    assert wait_until(lambda: up._connections == 0)


def test_stop_closes_open_connections(make_service):
    up = make_service("up")
    peer = raw_client(up)
    assert wait_until(lambda: len(up._serving) == 1)
    up.stop()
    with pytest.raises(OSError):
        peer.recv()