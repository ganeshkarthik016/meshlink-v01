import queue
import random
import socket
import time

import pytest

from p2pchat import config
from p2pchat.chat import encode_chat
from p2pchat.cli import Cli
from p2pchat.crypto import encrypt_packet
from p2pchat.files import FileEntry, FileError, encode_announce
from p2pchat.node import Node
from p2pchat.packet import PacketType, new_message_id
from p2pchat.peer import ConnType, Peer, Role
from p2pchat.transfer import DownloadError

HS_KEY = b"h" * 32
MSG_KEY = b"m" * 32
PASSWORD = "correct horse"


def ident(n):
    return bytes([n]) * config.SENDER_ID_SIZE


def wait_until(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


def make_file(directory, name, size, seed=0):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(random.Random(seed).randbytes(size))
    return path


@pytest.fixture
def make_node(tmp_path):
    nodes = []
    counter = [0]

    def make(name="node", files=True):
        counter[0] += 1
        announced = queue.Queue()
        chats = queue.Queue()
        node = Node(
            ident(counter[0]), HS_KEY, MSG_KEY, name,
            on_chat=lambda sender_id, nickname, text: chats.put(text),
            host="127.0.0.1", port=0,
            file_port=0 if files else None,
            download_dir=tmp_path / f"{name}-downloads",
            advertise_host="127.0.0.1",
            on_file=announced.put,
        )
        node.start()
        node.announced = announced
        node.chats = chats
        nodes.append(node)
        return node

    yield make
    for node in nodes:
        node.stop()


def link(a, b):
    assert a.connect("127.0.0.1", b.port) is True
    assert wait_until(lambda: a.peer_count() >= 1 and b.peer_count() >= 1)


def quiet(q, wait=0.4):
    time.sleep(wait)
    return q.empty()


# --- announcing ----------------------------------------------------------------------------------

def test_a_shared_file_is_announced_to_a_peer(make_node, tmp_path):
    a, b = make_node("a"), make_node("b")
    link(a, b)
    source = make_file(tmp_path / "src", "photo.png", 5000)
    entry, told = a.share_file(source)
    assert told == 1
    heard = b.announced.get(timeout=5)
    assert heard == entry
    assert heard.uploader_id == a.node_id
    assert b.files.table.entries() == [entry]


def test_the_announced_file_can_be_downloaded(make_node, tmp_path):
    a, b = make_node("a"), make_node("b")
    link(a, b)
    source = make_file(tmp_path / "src", "photo.png", 3 * config.CHUNK_SIZE + 7)
    a.share_file(source)
    entry = b.announced.get(timeout=5)
    result = b.files.download(entry)
    assert result.read_bytes() == source.read_bytes()


def test_the_uploader_does_not_hear_its_own_announcement(make_node, tmp_path):
    a, b = make_node("a"), make_node("b")
    link(a, b)
    entry, _ = a.share_file(make_file(tmp_path / "src", "a.txt", 100))
    b.announced.get(timeout=5)
    assert quiet(a.announced)
    assert a.files.table.entries() == [entry]   # but it is in our own list


def test_announcements_cross_a_middle_node(make_node, tmp_path):
    a, b, c = make_node("a"), make_node("b"), make_node("c")
    link(a, b)
    link(c, b)
    source = make_file(tmp_path / "src", "far.bin", 2000)
    a.share_file(source)
    entry = c.announced.get(timeout=5)
    assert entry.uploader_id == a.node_id
    assert c.files.download(entry).read_bytes() == source.read_bytes()   # straight from a


def test_a_node_without_file_sharing_still_relays_announcements(make_node, tmp_path):
    a, middle, c = make_node("a"), make_node("middle", files=False), make_node("c")
    link(a, middle)
    link(c, middle)
    a.share_file(make_file(tmp_path / "src", "x.bin", 100))
    assert c.announced.get(timeout=5).name == "x.bin"
    assert middle.files is None


def test_a_loop_does_not_announce_twice(make_node, tmp_path):
    a, b, c = make_node("a"), make_node("b"), make_node("c")
    link(a, b)
    link(b, c)
    link(c, a)
    a.share_file(make_file(tmp_path / "src", "once.bin", 100))
    b.announced.get(timeout=5)
    c.announced.get(timeout=5)
    assert quiet(b.announced) and quiet(c.announced)


def test_sharing_the_same_file_twice_lists_it_once(make_node, tmp_path):
    a, b = make_node("a"), make_node("b")
    link(a, b)
    source = make_file(tmp_path / "src", "twice.bin", 100)
    a.share_file(source)
    b.announced.get(timeout=5)
    a.share_file(source)   # a second announcement of the same content
    assert quiet(b.announced)
    assert len(b.files.table.entries()) == 1


def test_two_different_files_with_one_name(make_node, tmp_path):
    a, b = make_node("a"), make_node("b")
    link(a, b)
    a.share_file(make_file(tmp_path / "one", "report.pdf", 100, seed=1))
    a.share_file(make_file(tmp_path / "two", "report.pdf", 100, seed=2))
    assert wait_until(lambda: len(b.files.table.entries()) == 2)


def test_share_with_no_peers_tells_nobody(make_node, tmp_path):
    a = make_node("a")
    entry, told = a.share_file(make_file(tmp_path / "src", "a.txt", 10))
    assert told == 0
    assert a.files.table.entries() == [entry]


def test_share_when_file_sharing_is_off(make_node, tmp_path):
    a = make_node("a", files=False)
    with pytest.raises(RuntimeError):
        a.share_file(make_file(tmp_path / "src", "a.txt", 10))


def test_share_rejects_bad_files(make_node, tmp_path):
    a = make_node("a")
    with pytest.raises(FileError):
        a.share_file(tmp_path / "missing.txt")


def test_the_table_size_limit_applies_to_announcements(make_node, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "FILE_TABLE_MAX", 1)
    a, b = make_node("a"), make_node("b")
    link(a, b)
    a.share_file(make_file(tmp_path / "src", "one.bin", 100, seed=1))
    b.announced.get(timeout=5)
    a.share_file(make_file(tmp_path / "src", "two.bin", 100, seed=2))
    assert quiet(b.announced)
    assert len(b.files.table.entries()) == 1


def test_a_stopped_uploader_cannot_be_downloaded_from(make_node, tmp_path):
    a, b = make_node("a"), make_node("b")
    link(a, b)
    a.share_file(make_file(tmp_path / "src", "a.bin", 100))
    entry = b.announced.get(timeout=5)
    a.stop()
    with pytest.raises(OSError):
        b.files.download(entry)


# --- hostile announcements ----------------------------------------------------------------------------

def raw_connection(node):
    sock = socket.create_connection(("127.0.0.1", node.port))
    peer = Peer(sock, "raw", HS_KEY, ident(99), ConnType.MESH, Role.INITIATOR)
    peer.handshake()
    assert wait_until(lambda: node.peer_count() == 1)
    return peer


def announce_packet(entry, sender_id=ident(99), plaintext=None):
    return encrypt_packet(
        MSG_KEY,
        packet_type=PacketType.FILE_ANNOUNCE,
        ttl=5,
        message_id=new_message_id(),
        sender_id=sender_id,
        plaintext=encode_announce(entry) if plaintext is None else plaintext,
    )


def chat_packet(text="still alive"):
    return encrypt_packet(
        MSG_KEY, packet_type=PacketType.CHAT, ttl=5, message_id=new_message_id(),
        sender_id=ident(99), plaintext=encode_chat("raw", text),
    )


def an_entry(uploader=ident(99), **overrides):
    fields = dict(file_id=b"\x42" * 32, name="x.bin", size=100, uploader_id=uploader,
                  host="127.0.0.1", port=1234)
    fields.update(overrides)
    return FileEntry(**fields)


def test_an_announcement_for_someone_elses_file_is_dropped(make_node):
    b = make_node("b")
    raw = raw_connection(b)
    forged = announce_packet(an_entry(uploader=ident(5)), sender_id=ident(99))   # not the sender's own file
    raw.send_packet(forged)
    raw.send_packet(chat_packet())
    assert b.chats.get(timeout=5) == "still alive"
    assert b.files.table.entries() == []
    raw.close()


def test_a_valid_announcement_from_a_raw_peer_is_accepted(make_node):
    b = make_node("b")
    raw = raw_connection(b)
    raw.send_packet(announce_packet(an_entry()))
    assert b.announced.get(timeout=5).name == "x.bin"
    raw.close()


def test_a_garbage_announcement_is_dropped_and_the_node_carries_on(make_node):
    b = make_node("b")
    raw = raw_connection(b)
    raw.send_packet(announce_packet(an_entry(), plaintext=b"this is not an announcement"))
    raw.send_packet(announce_packet(an_entry(), plaintext=b""))
    raw.send_packet(chat_packet())
    assert b.chats.get(timeout=5) == "still alive"
    assert b.files.table.entries() == []
    assert b.peer_count() == 1
    raw.close()


def test_a_bad_announcement_is_not_forwarded(make_node):
    a, b = make_node("a"), make_node("b")
    link(b, a)
    raw = raw_connection_to(b)
    raw.send_packet(announce_packet(an_entry(uploader=ident(5)), sender_id=ident(99)))
    assert quiet(a.announced)
    assert a.files.table.entries() == []
    raw.close()


def raw_connection_to(node):
    sock = socket.create_connection(("127.0.0.1", node.port))
    peer = Peer(sock, "raw", HS_KEY, ident(99), ConnType.MESH, Role.INITIATOR)
    peer.handshake()
    assert wait_until(lambda: node.peer_count() == 2)
    return peer


def test_a_crashing_file_callback_does_not_stop_the_node(tmp_path):
    chats = queue.Queue()

    def bad_callback(entry):
        raise RuntimeError("bug in the display code")

    node = Node(ident(60), HS_KEY, MSG_KEY, "n", lambda s, n, t: chats.put(t),
                host="127.0.0.1", port=0, file_port=0, download_dir=tmp_path / "d", on_file=bad_callback)
    node.start()
    try:
        raw = raw_connection(node)
        raw.send_packet(announce_packet(an_entry()))
        raw.send_packet(chat_packet())
        assert chats.get(timeout=5) == "still alive"
        assert len(node.files.table.entries()) == 1
        raw.close()
    finally:
        node.stop()


# --- the CLI --------------------------------------------------------------------------------------------

@pytest.fixture
def make_cli(tmp_path):
    clis = []

    def make(nickname, passwords=(PASSWORD, PASSWORD), file_port=0):
        lines = []
        answers = iter(passwords)
        cli = Cli(nickname, host="127.0.0.1", port=0, out=lines.append,
                  ask_password=lambda prompt: next(answers),
                  file_port=file_port, download_dir=tmp_path / f"{nickname}-downloads",
                  advertise_host="127.0.0.1")
        cli.lines = lines
        cli.downloads = tmp_path / f"{nickname}-downloads"
        clis.append(cli)
        return cli

    yield make
    for cli in clis:
        cli.shutdown()


def said(cli, fragment):
    return any(fragment in line for line in cli.lines)


def connected_clis(make_cli):
    alice = make_cli("alice")
    bob = make_cli("bob", passwords=(PASSWORD,))
    alice.handle_line("/create lab")
    bob.handle_line("/join lab")
    bob.handle_line(f"/connect 127.0.0.1:{alice.node.port}")
    assert wait_until(lambda: alice.node.peer_count() == 1)
    return alice, bob


def test_share_list_and_download_through_the_cli(make_cli, tmp_path):
    alice, bob = connected_clis(make_cli)
    source = make_file(tmp_path / "src", "holiday photo.png", 2 * config.CHUNK_SIZE + 5)

    alice.handle_line(f"/share {source}")
    assert said(alice, "sharing holiday photo.png")
    assert said(alice, "1 peer(s) told")
    assert wait_until(lambda: said(bob, "shared holiday photo.png"))

    bob.handle_line("/files")
    assert said(bob, "holiday photo.png")
    assert said(bob, "(from ")

    bob.handle_line("/get 1")
    assert said(bob, "downloading holiday photo.png")
    assert wait_until(lambda: said(bob, "downloaded holiday photo.png"))
    assert (bob.downloads / "holiday photo.png").read_bytes() == source.read_bytes()


def test_get_by_hash_prefix(make_cli, tmp_path):
    alice, bob = connected_clis(make_cli)
    source = make_file(tmp_path / "src", "a.bin", 1000)
    alice.handle_line(f"/share {source}")
    assert wait_until(lambda: len(bob.node.files.table.entries()) == 1)
    prefix = bob.node.files.table.entries()[0].file_id.hex()[:6]
    bob.handle_line(f"/get {prefix}")
    assert wait_until(lambda: said(bob, "downloaded a.bin"))


def test_share_accepts_a_quoted_path(make_cli, tmp_path):
    alice, _ = connected_clis(make_cli)
    source = make_file(tmp_path / "my files", "a b.txt", 10)
    alice.handle_line(f"/share '{source}'")
    assert said(alice, "sharing a b.txt")


def test_progress_is_reported_in_quarters(make_cli, tmp_path):
    alice, bob = connected_clis(make_cli)
    alice.handle_line(f"/share {make_file(tmp_path / 'src', 'big.bin', 8 * config.CHUNK_SIZE)}")
    assert wait_until(lambda: len(bob.node.files.table.entries()) == 1)
    bob.handle_line("/get 1")
    assert wait_until(lambda: said(bob, "downloaded big.bin"))
    assert said(bob, "big.bin: 25%") and said(bob, "big.bin: 50%") and said(bob, "big.bin: 75%")


def test_you_cannot_download_your_own_file(make_cli, tmp_path):
    alice, _ = connected_clis(make_cli)
    alice.handle_line(f"/share {make_file(tmp_path / 'src', 'mine.bin', 100)}")
    alice.handle_line("/get 1")
    assert said(alice, "your own file")


def test_files_when_nothing_is_shared(make_cli):
    alice, _ = connected_clis(make_cli)
    alice.handle_line("/files")
    assert said(alice, "no files shared yet")


def test_get_with_bad_arguments(make_cli, tmp_path):
    alice, bob = connected_clis(make_cli)
    alice.handle_line(f"/share {make_file(tmp_path / 'src', 'a.bin', 100)}")
    assert wait_until(lambda: len(bob.node.files.table.entries()) == 1)
    bob.handle_line("/get")
    bob.handle_line("/get 7")
    bob.handle_line("/get zzzz")
    bob.handle_line("/get dead")
    assert said(bob, "usage: /get")
    assert said(bob, "no file number 7")
    assert said(bob, "at least 4 characters")
    assert said(bob, "no file starts with dead")


def test_share_with_bad_arguments(make_cli, tmp_path):
    alice, _ = connected_clis(make_cli)
    alice.handle_line("/share")
    alice.handle_line(f"/share {tmp_path / 'missing.txt'}")
    alice.handle_line(f"/share {tmp_path}")
    assert said(alice, "usage: /share")
    assert said(alice, "is not a file")


def test_share_with_nobody_connected_warns(make_cli, tmp_path):
    alice = make_cli("alice")
    alice.handle_line("/create lab")
    alice.handle_line(f"/share {make_file(tmp_path / 'src', 'a.txt', 10)}")
    assert said(alice, "0 peer(s) told")
    assert said(alice, "nobody was told")


def test_file_commands_before_joining(make_cli):
    cli = make_cli("alice")
    cli.handle_line("/share x")
    cli.handle_line("/files")
    cli.handle_line("/get 1")
    assert said(cli, "join or create a room first")
    assert said(cli, "file sharing is not available")


def test_file_sharing_switched_off(make_cli):
    cli = make_cli("alice", file_port=None)
    cli.handle_line("/create lab")
    cli.handle_line("/share x")
    cli.handle_line("/files")
    assert said(cli, "file sharing is off")
    assert said(cli, "file sharing is not available")


def test_a_failed_download_is_reported(make_cli, tmp_path):
    alice, bob = connected_clis(make_cli)
    source = make_file(tmp_path / "src", "gone.bin", 1000)
    alice.handle_line(f"/share {source}")
    assert wait_until(lambda: len(bob.node.files.table.entries()) == 1)
    source.unlink()
    bob.handle_line("/get 1")
    assert wait_until(lambda: said(bob, "download of gone.bin failed"))
    assert said(bob, "missing or has changed")


def test_downloading_from_an_uploader_that_left_is_reported(make_cli, tmp_path):
    alice, bob = connected_clis(make_cli)
    alice.handle_line(f"/share {make_file(tmp_path / 'src', 'a.bin', 1000)}")
    assert wait_until(lambda: len(bob.node.files.table.entries()) == 1)
    alice.shutdown()
    bob.handle_line("/get 1")
    assert wait_until(lambda: said(bob, "cannot reach the uploader"))


def test_a_file_name_with_terminal_codes_is_shown_safely(make_cli, tmp_path):
    alice, bob = connected_clis(make_cli)
    alice.handle_line(f"/share {make_file(tmp_path / 'src', 'evil\x1b[2Jname.txt', 10)}")
    assert wait_until(lambda: len(bob.node.files.table.entries()) == 1)
    bob.handle_line("/files")
    assert not any("\x1b" in line for line in bob.lines)
    assert bob.node.files.table.entries()[0].name == "evil[2Jname.txt"