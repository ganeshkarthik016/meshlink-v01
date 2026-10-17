import time

import pytest

from p2pchat import config
from p2pchat.cli import Cli, clean_nickname, parse_address, parse_command

PASSWORD = "correct horse"


def wait_until(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


# --- parse_command ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "line, expected",
    [
        ("/join lab", ("join", "lab")),
        ("/Peers", ("peers", "")),
        ("  /connect 1.2.3.4:5  ", ("connect", "1.2.3.4:5")),
        ("/nick two words", ("nick", "two words")),
        ("/", ("", "")),
        ("hello", None),
        ("hello /join", None),
        ("", None),
    ],
)
def test_parse_command(line, expected):
    assert parse_command(line) == expected


# --- parse_address -----------------------------------------------------------------------

def test_address_with_port():
    assert parse_address("192.168.1.5:50002", 1) == ("192.168.1.5", 50002)


def test_address_without_port_uses_the_default():
    assert parse_address("192.168.1.5", 4242) == ("192.168.1.5", 4242)


@pytest.mark.parametrize("text", ["", ":5", "1.2.3.4:", "1.2.3.4:abc", "1.2.3.4:0", "1.2.3.4:70000", "1.2.3.4:-5"])
def test_bad_addresses(text):
    with pytest.raises(ValueError):
        parse_address(text, 1)


# --- clean_nickname --------------------------------------------------------------------------

def test_clean_nickname():
    assert clean_nickname("  ganesh ") == "ganesh"
    assert clean_nickname("ga\x1b[31mnesh") == "ga[31mnesh"
    assert clean_nickname("") is None
    assert clean_nickname("\x1b\x1b") is None
    assert clean_nickname("n" * (config.MAX_NICKNAME_BYTES + 1)) is None


# --- the Cli with real nodes ---------------------------------------------------------------------

@pytest.fixture
def make_cli():
    clis = []

    def make(nickname="alice", passwords=(PASSWORD, PASSWORD)):
        lines = []
        answers = iter(passwords)
        cli = Cli(nickname, host="127.0.0.1", port=0, out=lines.append,
                  ask_password=lambda prompt: next(answers))
        cli.lines = lines
        clis.append(cli)
        return cli

    yield make
    for cli in clis:
        cli.shutdown()


def said(cli, fragment):
    return any(fragment in line for line in cli.lines)


def test_help(make_cli):
    cli = make_cli()
    assert cli.handle_line("/help") is True
    assert said(cli, "/connect")


def test_unknown_command(make_cli):
    cli = make_cli()
    cli.handle_line("/frobnicate")
    assert said(cli, "unknown command")


def test_blank_line_does_nothing(make_cli):
    cli = make_cli()
    assert cli.handle_line("   ") is True
    assert cli.lines == []


def test_chat_before_joining_a_room(make_cli):
    cli = make_cli()
    cli.handle_line("hello")
    assert said(cli, "join or create a room first")


def test_connect_and_peers_before_joining(make_cli):
    cli = make_cli()
    cli.handle_line("/connect 127.0.0.1:1")
    cli.handle_line("/peers")
    assert said(cli, "join or create a room first")
    assert said(cli, "not in a room")


def test_create_room(make_cli):
    cli = make_cli()
    cli.handle_line("/create lab")
    assert cli.node is not None
    assert said(cli, "room 'lab' ready")
    assert said(cli, f":{cli.node.port}")


def test_create_needs_matching_passwords(make_cli):
    cli = make_cli(passwords=(PASSWORD, "something else"))
    cli.handle_line("/create lab")
    assert cli.node is None
    assert said(cli, "do not match")


def test_short_password_is_refused(make_cli):
    cli = make_cli(passwords=("short", "short"))
    cli.handle_line("/create lab")
    assert cli.node is None
    assert said(cli, "at least")


def test_create_without_a_room_name(make_cli):
    cli = make_cli()
    cli.handle_line("/create")
    assert cli.node is None
    assert said(cli, "usage")


def test_cannot_enter_a_second_room(make_cli):
    cli = make_cli()
    cli.handle_line("/create lab")
    cli.handle_line("/join other")
    assert said(cli, "already in a room")


def test_two_people_chat(make_cli):
    alice = make_cli("alice")
    bob = make_cli("bob", passwords=(PASSWORD,))
    alice.handle_line("/create lab")
    bob.handle_line("/join lab")
    bob.handle_line(f"/connect 127.0.0.1:{alice.node.port}")
    assert said(bob, "connected")
    assert wait_until(lambda: alice.node.peer_count() == 1)

    alice.handle_line("hello bob")
    assert said(alice, "you: hello bob")
    assert wait_until(lambda: said(bob, "alice: hello bob"))

    bob.handle_line("hi alice")
    assert wait_until(lambda: said(alice, "bob: hi alice"))


def test_peers_lists_the_connection(make_cli):
    alice = make_cli("alice")
    bob = make_cli("bob", passwords=(PASSWORD,))
    alice.handle_line("/create lab")
    bob.handle_line("/join lab")
    bob.handle_line(f"/connect 127.0.0.1:{alice.node.port}")
    bob.handle_line("/peers")
    assert said(bob, alice.node.node_id.hex()[:8])


def test_chat_with_nobody_connected_warns(make_cli):
    cli = make_cli()
    cli.handle_line("/create lab")
    cli.handle_line("anyone?")
    assert said(cli, "no peers connected")


def test_wrong_password_is_reported(make_cli):
    alice = make_cli("alice")
    eve = make_cli("eve", passwords=("a different password",))
    alice.handle_line("/create lab")
    eve.handle_line("/join lab")
    eve.handle_line(f"/connect 127.0.0.1:{alice.node.port}")
    assert said(eve, "wrong password")
    assert alice.node.peer_count() == 0


def test_connecting_to_the_wrong_room_is_reported(make_cli):
    alice = make_cli("alice")
    bob = make_cli("bob", passwords=(PASSWORD,))
    alice.handle_line("/create lab")
    bob.handle_line("/join other-room")   # same password, different room
    bob.handle_line(f"/connect 127.0.0.1:{alice.node.port}")
    assert said(bob, "wrong password or room")


def test_connect_to_nothing(make_cli):
    cli = make_cli()
    cli.handle_line("/create lab")
    cli.handle_line("/connect 127.0.0.1:1")   # port 1: nothing listens there
    assert said(cli, "cannot reach")


def test_connect_with_a_bad_address(make_cli):
    cli = make_cli()
    cli.handle_line("/create lab")
    cli.handle_line("/connect 1.2.3.4:banana")
    assert said(cli, "not a port number")


def test_connecting_twice_says_so(make_cli):
    alice = make_cli("alice")
    bob = make_cli("bob", passwords=(PASSWORD,))
    alice.handle_line("/create lab")
    bob.handle_line("/join lab")
    bob.handle_line(f"/connect 127.0.0.1:{alice.node.port}")
    bob.handle_line(f"/connect 127.0.0.1:{alice.node.port}")
    assert said(bob, "already connected")


def test_nick_changes_the_name_others_see(make_cli):
    alice = make_cli("alice")
    bob = make_cli("bob", passwords=(PASSWORD,))
    alice.handle_line("/create lab")
    bob.handle_line("/join lab")
    bob.handle_line(f"/connect 127.0.0.1:{alice.node.port}")
    assert wait_until(lambda: alice.node.peer_count() == 1)
    alice.handle_line("/nick alicia")
    alice.handle_line("renamed")
    assert wait_until(lambda: said(bob, "alicia: renamed"))


def test_bad_nick(make_cli):
    cli = make_cli()
    cli.handle_line("/nick")
    assert said(cli, "usage: /nick")
    assert cli.nickname == "alice"


def test_text_that_looks_like_an_escape_code_is_cleaned(make_cli):
    alice = make_cli("alice")
    bob = make_cli("bob", passwords=(PASSWORD,))
    alice.handle_line("/create lab")
    bob.handle_line("/join lab")
    bob.handle_line(f"/connect 127.0.0.1:{alice.node.port}")
    assert wait_until(lambda: alice.node.peer_count() == 1)
    alice.handle_line("hi\x1b[2Jthere")
    assert wait_until(lambda: said(bob, "alice: hi[2Jthere"))
    assert not any("\x1b" in line for line in bob.lines)


def test_quit_stops_the_node(make_cli):
    cli = make_cli()
    cli.handle_line("/create lab")
    node = cli.node
    assert cli.handle_line("/quit") is False
    assert cli.node is None
    with pytest.raises(OSError):
        node._server.getsockname()   # the listening socket is closed


def test_exit_also_quits(make_cli):
    cli = make_cli()
    assert cli.handle_line("/exit") is False