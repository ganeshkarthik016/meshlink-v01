import hashlib
import socket
import struct

import pytest

from p2pchat import config
from p2pchat.files import (
    FileEntry,
    FileError,
    FileTable,
    _ANNOUNCE,
    decode_announce,
    encode_announce,
    format_size,
    hash_file,
    sanitize_filename,
)

UPLOADER = b"U" * config.SENDER_ID_SIZE


def entry(**overrides):
    fields = dict(
        file_id=b"\x11" * 32, name="photo.png", size=1234,
        uploader_id=UPLOADER, host="192.168.1.20", port=50003,
    )
    fields.update(overrides)
    return FileEntry(**fields)


# --- sanitize_filename --------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw, cleaned",
    [
        ("photo.png", "photo.png"),
        ("my notes (final).txt", "my notes (final).txt"),
        ("../../etc/passwd", "passwd"),
        ("/etc/shadow", "shadow"),
        ("C:\\Users\\me\\a.txt", "a.txt"),
        ("a<b>c:d.txt", "a_b_c_d.txt"),
        (".hidden", "hidden"),
        ("  spaced.txt  ", "spaced.txt"),
        ("evil\x1b[31m.txt", "evil[31m.txt"),
        ("गणेश-日本語.txt", "गणेश-日本語.txt"),
    ],
)
def test_sanitize_filename(raw, cleaned):
    assert sanitize_filename(raw) == cleaned


@pytest.mark.parametrize("raw", ["", " ", ".", "..", "...", "/", "a/", "\x1b\x00", "../"])
def test_unusable_names_are_refused(raw):
    with pytest.raises(FileError):
        sanitize_filename(raw)


def test_name_length_limit():
    assert sanitize_filename("n" * config.MAX_FILE_NAME_BYTES) == "n" * config.MAX_FILE_NAME_BYTES
    with pytest.raises(FileError):
        sanitize_filename("n" * (config.MAX_FILE_NAME_BYTES + 1))


# --- announcements ---------------------------------------------------------------------------

def test_announce_roundtrip():
    original = entry()
    assert decode_announce(encode_announce(original)) == original


def test_announce_roundtrip_unicode_name():
    original = entry(name="गणेश-日本語.txt")
    assert decode_announce(encode_announce(original)) == original


def test_announce_is_small():
    assert len(encode_announce(entry(name="n" * config.MAX_FILE_NAME_BYTES))) < config.MAX_PAYLOAD_SIZE - 16


def raw_announce(name=b"photo.png", size=1234, host="192.168.1.20", port=50003, name_length=None, extra=b""):
    return _ANNOUNCE.pack(
        b"\x11" * 32, size, UPLOADER, socket.inet_aton(host), port,
        len(name) if name_length is None else name_length,
    ) + name + extra


def test_raw_announce_helper_matches_the_real_format():
    assert decode_announce(raw_announce()) == entry()


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"x" * 10,
        b"x" * _ANNOUNCE.size,                                      # no name at all
        raw_announce(name_length=0, name=b""),
        raw_announce(name_length=200, name=b"x" * 200),              # name over the limit
        raw_announce(name_length=20, name=b"short"),                 # claims more than it has
        raw_announce(extra=b"trailing bytes"),                       # more than it claims
        raw_announce(name=b"\xff\xfe\xfd"),                          # not UTF-8
        raw_announce(name=b".."),                                    # nothing usable left
        raw_announce(size=0),
        raw_announce(size=config.MAX_FILE_SIZE + 1),
        raw_announce(port=0),
        raw_announce(host="0.0.0.0"),
        raw_announce(host="224.0.0.1"),
        raw_announce(host="255.255.255.255"),
    ],
)
def test_bad_announcements_are_rejected(payload):
    with pytest.raises(FileError):
        decode_announce(payload)


def test_a_dangerous_name_is_cleaned_when_decoded():
    decoded = decode_announce(raw_announce(name=b"../../.ssh/authorized_keys"))
    assert decoded.name == "authorized_keys"


def test_largest_allowed_size_is_accepted():
    assert decode_announce(raw_announce(size=config.MAX_FILE_SIZE)).size == config.MAX_FILE_SIZE


@pytest.mark.parametrize(
    "bad",
    [
        dict(size=0),
        dict(size=config.MAX_FILE_SIZE + 1),
        dict(file_id=b"short"),
        dict(uploader_id=b"short"),
        dict(port=0),
        dict(port=70000),
        dict(host="not an ip"),
        dict(host="0.0.0.0"),
        dict(name=""),
    ],
)
def test_encode_refuses_bad_entries(bad):
    with pytest.raises(FileError):
        encode_announce(entry(**bad))


# --- the file table -----------------------------------------------------------------------------

def table_with(*entries):
    table = FileTable()
    for item in entries:
        table.add(item)
    return table


def test_table_keeps_order_and_ignores_repeats():
    a = entry(file_id=b"\xaa" * 32, name="a.txt")
    b = entry(file_id=b"\xbb" * 32, name="b.txt")
    table = FileTable()
    assert table.add(a) is True
    assert table.add(b) is True
    assert table.add(a) is False
    assert table.entries() == [a, b]


def test_same_name_different_files_are_both_kept():
    a = entry(file_id=b"\xaa" * 32, name="report.pdf")
    b = entry(file_id=b"\xbb" * 32, name="report.pdf")
    assert len(table_with(a, b).entries()) == 2


def test_table_size_limit(monkeypatch):
    monkeypatch.setattr(config, "FILE_TABLE_MAX", 2)
    table = table_with(entry(file_id=b"\x01" * 32), entry(file_id=b"\x02" * 32))
    assert table.add(entry(file_id=b"\x03" * 32)) is False
    assert len(table.entries()) == 2


def test_find_by_number():
    a = entry(file_id=b"\xaa" * 32)
    b = entry(file_id=b"\xbb" * 32)
    table = table_with(a, b)
    assert table.find("1") == a
    assert table.find(" 2 ") == b


@pytest.mark.parametrize("token", ["0", "3", "999"])
def test_find_by_a_number_that_does_not_exist(token):
    with pytest.raises(LookupError):
        table_with(entry()).find(token)


def test_find_by_hash_prefix():
    a = entry(file_id=bytes.fromhex("3fa91c2b") + b"\x00" * 28)
    b = entry(file_id=bytes.fromhex("8c01d2aa") + b"\x00" * 28)
    table = table_with(a, b)
    assert table.find("3fa9") == a
    assert table.find("8C01D2") == b          # case does not matter


def test_find_by_a_hash_prefix_that_matches_nothing():
    with pytest.raises(LookupError):
        table_with(entry()).find("dead")


def test_find_by_an_ambiguous_prefix():
    a = entry(file_id=bytes.fromhex("3fa91c2b") + b"\x00" * 28)
    b = entry(file_id=bytes.fromhex("3fa9ffff") + b"\x00" * 28)
    with pytest.raises(LookupError, match="2 files"):
        table_with(a, b).find("3fa9")


@pytest.mark.parametrize("token", ["", "  ", "zz", "3f", "xyzxyz", "3fa"])
def test_find_with_unusable_tokens(token):
    with pytest.raises(LookupError):
        table_with(entry(file_id=bytes.fromhex("3fa91c2b") + b"\x00" * 28)).find(token)


def test_a_long_all_digit_token_is_a_hash_prefix_not_a_number():
    a = entry(file_id=bytes.fromhex("12345678") + b"\x00" * 28)
    assert table_with(a).find("1234") == a


# --- hashing and sizes -----------------------------------------------------------------------------

def test_hash_file(tmp_path):
    content = b"hello world" * 1000
    path = tmp_path / "f.bin"
    path.write_bytes(content)
    assert hash_file(path) == (hashlib.sha256(content).digest(), len(content))


def test_hash_file_larger_than_one_block(tmp_path):
    content = bytes(range(256)) * 10_000   # 2.5 MB
    path = tmp_path / "big.bin"
    path.write_bytes(content)
    assert hash_file(path) == (hashlib.sha256(content).digest(), len(content))


def test_hash_of_a_missing_file(tmp_path):
    with pytest.raises(OSError):
        hash_file(tmp_path / "missing")


@pytest.mark.parametrize(
    "count, text",
    [(0, "0 B"), (999, "999 B"), (1024, "1.0 KB"), (1536, "1.5 KB"), (5 * 1024 * 1024, "5.0 MB"),
     (100 * 1024 * 1024, "100.0 MB"), (3 * 1024**3, "3.0 GB")],
)
def test_format_size(count, text):
    assert format_size(count) == text