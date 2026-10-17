import queue
import time

import pytest

from p2pchat import config
from p2pchat.cli import Cli
from p2pchat.node import Node, new_node_id

HS_KEY = b"h" * 32
MSG_KEY = b"m" * 32
OTHER_HS_KEY = b"x" * 32
OTHER_MSG_KEY = b"y" * 32
PASSWORD = "correct horse"


@pytest.fixture(autouse=True)
def short_reply_window(monkeypatch):
    # Real searches wait 2 seconds for replies. Tests on one machine need far less.
    monkeypatch.setattr(config, "DISCOVERY_WAIT", 0.4)


def wait_until(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


@pytest.fixture
def make_node():
    nodes = []

    def make(name="node", room="lab", handshake_key=HS_KEY, message_key=MSG_KEY, discovery=True):
        received = queue.Queue()
        node = Node(
            new_node_id(), handshake_key, message_key, name,
            on_chat=lambda sender_id, nickname, text: received.put(text),
            host="127.0.0.1", port=0,
            room_id=room, discovery_port=0 if discovery else None,
        )
        node.start()
        node.received = received
        nodes.append(node)
        return node

    yield make
    for node in nodes:
        node.stop()


def aim_at(*nodes):
    return [("127.0.0.1", node.discovery_port) for node in nodes]


# --- Node.find_peers -------------------------------------------------------------------------

def test_discovery_port_is_exposed(make_node):
    assert make_node().discovery_port > 0


def test_node_without_discovery(make_node):
    node = make_node(discovery=False)
    assert node.discovery_port is None
    assert node.find_peers() == (0, 0)


def test_finds_and_connects_to_nodes(make_node):
    a, b, c = make_node("a"), make_node("b"), make_node("c")
    assert c.find_peers(targets=aim_at(a, b)) == (2, 2)
    assert wait_until(lambda: a.peer_count() == 1 and b.peer_count() == 1)
    assert c.peer_count() == 2


def test_chat_works_over_discovered_links(make_node):
    a, b = make_node("a"), make_node("b")
    assert b.find_peers(targets=aim_at(a)) == (1, 1)
    assert wait_until(lambda: a.peer_count() == 1)
    b.send_chat("found you")
    assert a.received.get(timeout=5) == "found you"


def test_stops_at_the_peer_target(make_node, monkeypatch):
    monkeypatch.setattr(config, "PEER_TARGET", 2)
    others = [make_node(f"n{i}") for i in range(4)]
    joiner = make_node("joiner")
    found, connected = joiner.find_peers(targets=aim_at(*others))
    assert found == 4
    assert connected == 2
    assert joiner.peer_count() == 2


def test_skips_nodes_we_are_already_linked_to(make_node):
    a, b, c = make_node("a"), make_node("b"), make_node("c")
    assert c.connect("127.0.0.1", a.port) is True
    assert c.find_peers(targets=aim_at(a, b)) == (2, 1)   # only b is new
    assert c.peer_count() == 2


def test_a_same_named_room_with_another_password_is_skipped(make_node):
    good = make_node("good")
    impostor = make_node("impostor", handshake_key=OTHER_HS_KEY, message_key=OTHER_MSG_KEY)
    joiner = make_node("joiner")
    found, connected = joiner.find_peers(targets=aim_at(good, impostor))
    assert found == 2          # both answered: they share the room name
    assert connected == 1      # but only the right password gets through
    assert joiner.peer_count() == 1
    assert impostor.peer_count() == 0


def test_other_rooms_do_not_answer(make_node):
    other = make_node("other", room="somewhere-else")
    joiner = make_node("joiner", room="lab")
    assert joiner.find_peers(targets=aim_at(other)) == (0, 0)


def test_a_full_node_does_not_answer(make_node, monkeypatch):
    monkeypatch.setattr(config, "PEER_MAX", 1)
    a, b, joiner = make_node("a"), make_node("b"), make_node("joiner")
    assert b.connect("127.0.0.1", a.port) is True   # a is now full
    assert wait_until(lambda: a.peer_count() == 1)
    assert joiner.find_peers(targets=aim_at(a)) == (0, 0)


def test_a_node_that_died_after_answering_is_skipped(make_node):
    a, b, joiner = make_node("a"), make_node("b"), make_node("joiner")
    candidates = joiner._discovery.search(wait=0.5, targets=aim_at(a, b))
    assert len(candidates) == 2
    b.stop()   # b goes away between the answer and the connection attempt
    assert joiner.find_peers(targets=aim_at(a, b))[1] >= 1   # a still gets connected
    assert joiner.peer_count() == 1


def test_stopping_a_node_stops_answering(make_node):
    a, joiner = make_node("a"), make_node("joiner")
    port = a.discovery_port
    a.stop()
    assert joiner.find_peers(targets=[("127.0.0.1", port)]) == (0, 0)


# --- the CLI: /join and /find ------------------------------------------------------------------

@pytest.fixture
def make_cli():
    clis = []

    def make(nickname="alice", passwords=(PASSWORD, PASSWORD), discovery_port=0):
        lines = []
        answers = iter(passwords)
        cli = Cli(nickname, host="127.0.0.1", port=0, out=lines.append,
                  ask_password=lambda prompt: next(answers), discovery_port=discovery_port)
        cli.lines = lines
        clis.append(cli)
        return cli

    yield make
    for cli in clis:
        cli.shutdown()


def said(cli, fragment):
    return any(fragment in line for line in cli.lines)


def test_join_finds_the_room_and_chats(make_cli):
    alice = make_cli("alice")
    bob = make_cli("bob", passwords=(PASSWORD,))
    alice.handle_line("/create lab")
    bob.discovery_targets = [("127.0.0.1", alice.node.discovery_port)]
    bob.handle_line("/join lab")
    assert said(bob, "1 node(s) answered, 1 new connection(s)")
    assert wait_until(lambda: alice.node.peer_count() == 1)
    bob.handle_line("found you")
    assert wait_until(lambda: said(alice, "bob: found you"))


def test_join_with_nobody_there(make_cli):
    bob = make_cli("bob", passwords=(PASSWORD,))
    bob.discovery_targets = [("127.0.0.1", 9)]   # nothing listens on port 9
    bob.handle_line("/join lab")
    assert said(bob, "nobody answered")
    assert bob.node is not None   # still in the room, waiting for others to find us


def test_find_repeats_the_search(make_cli):
    alice = make_cli("alice")
    bob = make_cli("bob", passwords=(PASSWORD,))
    alice.handle_line("/create lab")
    bob.discovery_targets = [("127.0.0.1", alice.node.discovery_port)]
    bob.handle_line("/join lab")
    bob.handle_line("/find")
    assert said(bob, "1 node(s) answered, 0 new connection(s)")


def test_find_before_joining(make_cli):
    cli = make_cli()
    cli.handle_line("/find")
    assert said(cli, "join or create a room first")


def test_join_with_discovery_off(make_cli):
    bob = make_cli("bob", passwords=(PASSWORD,), discovery_port=None)
    bob.handle_line("/join lab")
    assert said(bob, "discovery is off")
    assert bob.node is not None