"""Terminal interface: reads what you type, runs commands, prints chat.

A line starting with "/" is a command. Anything else is a chat message.

Cli holds the logic and is easy to test (it prints through a function it is
given). Terminal is the small helper that prints incoming chat without
wrecking the line you are in the middle of typing. main() wires them up.
"""

import argparse
import getpass
import logging
import sys
import threading
import time

try:
    import readline   # makes input() editable, and lets us see a half-typed line
except ImportError:   # e.g. Windows
    readline = None

from p2pchat import config
from p2pchat.chat import ChatError, sanitize
from p2pchat.crypto import derive_keys
from p2pchat.files import FileError, format_size
from p2pchat.netutil import local_ip
from p2pchat.node import Node, new_node_id
from p2pchat.peer import HandshakeError
from p2pchat.transfer import DownloadError

PROMPT = "> "

HELP = """\
/create <room>         start a new room (asks for a password twice)
/join <room>           join a room: looks for its nodes and connects (asks for the password)
/find                  look for nodes in the room again
/connect <ip[:port]>   connect to a node by address
/peers                 list connected peers
/share <path>          share a file with the room
/files                 list files shared in the room
/get <number|hash>     download a file (runs in the background)
/nick <name>           change your nickname
/help                  show this
/quit                  leave
Anything else is sent as a chat message."""


# --- small pure helpers (easy to test) ------------------------------------------------

def parse_command(line: str):
    """"/join lab" -> ("join", "lab"). Returns None if the line is not a command."""
    line = line.strip()
    if not line.startswith("/"):
        return None
    name, _, argument = line[1:].partition(" ")
    return name.lower(), argument.strip()


def parse_address(text: str, default_port: int) -> tuple[str, int]:
    """"192.168.1.5:50002" -> ("192.168.1.5", 50002). Raises ValueError if bad."""
    text = text.strip()
    host, sep, port_text = text.partition(":")
    host = host.strip()
    if not host:
        raise ValueError("usage: /connect <ip[:port]>")
    if not sep:
        return host, default_port
    try:
        port = int(port_text)
    except ValueError:
        raise ValueError(f"'{port_text}' is not a port number") from None
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return host, port


def unquote(text: str) -> str:
    """Remove one pair of quotes around a path (dragging a file into a terminal adds them)."""
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    return text


def clean_nickname(text: str):
    """The cleaned nickname, or None if it is empty or too long."""
    nickname = sanitize(text).strip()
    if not 1 <= len(nickname.encode()) <= config.MAX_NICKNAME_BYTES:
        return None
    return nickname


def clock() -> str:
    return time.strftime("%H:%M")


# --- printing without wrecking the line being typed --------------------------------------

class Terminal:
    """Thread-safe printing. Incoming chat arrives on another thread while you
    may be typing, so we clear the current line, print, then redraw the prompt
    and whatever you had typed so far."""

    def __init__(self):
        self._lock = threading.Lock()
        self.typing = False   # True only while the main thread waits in input()

    def print(self, line: str) -> None:
        with self._lock:
            if self.typing:
                typed = readline.get_line_buffer() if readline else ""
                sys.stdout.write("\r\x1b[K" + line + "\n" + PROMPT + typed)
            else:
                sys.stdout.write(line + "\n")
            sys.stdout.flush()


# --- the interface itself ------------------------------------------------------------------

class Cli:
    def __init__(self, nickname, host="0.0.0.0", port=config.MESH_PORT,
                 out=print, ask_password=getpass.getpass,
                 discovery_port=None, discovery_targets=None,
                 file_port=None, download_dir=None, advertise_host=None):
        self.nickname = nickname
        self.host = host
        self.port = port
        self.discovery_port = discovery_port        # None = discovery off
        self.discovery_targets = discovery_targets  # None = broadcast. Tests set this
        self.file_port = file_port                  # None = file sharing off
        self.download_dir = download_dir
        self.advertise_host = advertise_host
        self.out = out                    # a function that shows one line
        self._ask_password = ask_password
        self.node = None
        self._commands = {
            "help": self._cmd_help,
            "create": self._cmd_create,
            "join": self._cmd_join,
            "find": self._cmd_find,
            "connect": self._cmd_connect,
            "peers": self._cmd_peers,
            "share": self._cmd_share,
            "files": self._cmd_files,
            "get": self._cmd_get,
            "nick": self._cmd_nick,
            "quit": self._cmd_quit,
            "exit": self._cmd_quit,
        }

    def run(self, terminal: Terminal) -> None:
        """The main loop. Returns when the user quits."""
        self.out("p2pchat v0.1. Type /help for commands.")
        while True:
            terminal.typing = True
            try:
                line = input(PROMPT)
            except (EOFError, KeyboardInterrupt):   # Ctrl-D or Ctrl-C
                print()
                break
            finally:
                terminal.typing = False
            if not self.handle_line(line):
                break
        self.shutdown()

    def handle_line(self, line: str) -> bool:
        """Handle one line of input. Returns False when the user wants to quit."""
        line = line.strip()
        if not line:
            return True
        parsed = parse_command(line)
        if parsed is None:
            self._send_chat(line)
            return True
        name, argument = parsed
        handler = self._commands.get(name)
        if handler is None:
            self.out(f"unknown command /{name}. Try /help")
            return True
        return handler(argument) is not False   # a handler returns False to quit

    def shutdown(self) -> None:
        if self.node is not None:
            self.node.stop()
            self.node = None

    # --- commands -----------------------------------------------------------------------

    def _cmd_help(self, argument):
        self.out(HELP)

    def _cmd_create(self, argument):
        self._enter_room(argument, confirm=True)

    def _cmd_join(self, argument):
        if self._enter_room(argument, confirm=False):
            self._search()

    def _cmd_find(self, argument):
        if self.node is None:
            self.out("join or create a room first")
            return
        self._search()

    def _search(self) -> None:
        if self.node.discovery_port is None:
            self.out("discovery is off: use /connect ip:port")
            return
        self.out("looking for nodes in this room ...")
        found, connected = self.node.find_peers(targets=self.discovery_targets)
        if found == 0:
            self.out("nobody answered. You may be the first one here, or this network blocks broadcast. "
                     "Others can find you with /join, or use /connect ip:port")
        else:
            self.out(f"{found} node(s) answered, {connected} new connection(s). "
                     f"You now have {self.node.peer_count()} peer(s)")

    def _enter_room(self, room_id: str, confirm: bool) -> bool:
        """Derive the keys, start listening. Returns True if the room is ready."""
        if self.node is not None:
            self.out("you are already in a room. /quit and start again to use another")
            return False
        if not room_id:
            self.out("usage: /create <room>   or   /join <room>")
            return False
        password = self._ask_password("password: ")
        if confirm and self._ask_password("repeat password: ") != password:
            self.out("the passwords do not match")
            return False
        try:
            handshake_key, message_key = derive_keys(password, room_id)
        except ValueError as error:
            self.out(str(error))
            return False
        node = Node(new_node_id(), handshake_key, message_key, self.nickname,
                    self._on_chat, self.host, self.port,
                    room_id=room_id, discovery_port=self.discovery_port,
                    file_port=self.file_port, download_dir=self.download_dir,
                    advertise_host=self.advertise_host, on_file=self._on_file)
        try:
            node.start()
        except OSError as error:
            self.out(f"cannot start listening: {error}. Try another --port, --discovery-port or --file-port")
            return False
        self.node = node
        self.out(f"room '{room_id}' ready. Others can connect with:  /connect {local_ip()}:{node.port}")
        return True

    def _cmd_connect(self, argument):
        if self.node is None:
            self.out("join or create a room first")
            return
        try:
            host, port = parse_address(argument, config.MESH_PORT)
        except ValueError as error:
            self.out(str(error))
            return
        self.out(f"connecting to {host}:{port} ...")
        try:
            added = self.node.connect(host, port)
        except HandshakeError:
            self.out("could not join: wrong password or room, or that is not a p2pchat node")
        except OSError as error:
            self.out(f"cannot reach {host}:{port}: {error}")
        else:
            self.out("connected" if added else "you are already connected to that node")

    def _cmd_peers(self, argument):
        if self.node is None:
            self.out("not in a room")
            return
        peers = self.node.peer_info()
        if not peers:
            self.out("no peers connected")
            return
        for node_id, address in peers:
            self.out(f"  {node_id.hex()[:8]}  {address[0]}:{address[1]}")

    def _cmd_share(self, argument):
        if self.node is None:
            self.out("join or create a room first")
            return
        if self.node.files is None:
            self.out("file sharing is off")
            return
        path = unquote(argument)
        if not path:
            self.out("usage: /share <path to a file>")
            return
        try:
            entry, told = self.node.share_file(path)
        except FileError as error:
            self.out(str(error))
            return
        except OSError as error:
            self.out(f"cannot read that file: {error}")
            return
        self.out(f"sharing {entry.name} ({format_size(entry.size)}, id {entry.file_id.hex()[:8]}). "
                 f"{told} peer(s) told. Keep this program running so others can download it")
        if told == 0:
            self.out("(no peers connected: nobody was told about it)")

    def _cmd_files(self, argument):
        if self.node is None or self.node.files is None:
            self.out("file sharing is not available")
            return
        entries = self.node.files.table.entries()
        if not entries:
            self.out("no files shared yet. Files announced before you joined are not listed")
            return
        for number, entry in enumerate(entries, start=1):
            source = "you" if entry.uploader_id == self.node.node_id else entry.uploader_id.hex()[:8]
            self.out(f"  {number:>3}  {format_size(entry.size):>9}  {entry.file_id.hex()[:8]}  {entry.name}  (from {source})")

    def _cmd_get(self, argument):
        if self.node is None or self.node.files is None:
            self.out("file sharing is not available")
            return
        try:
            entry = self.node.files.table.find(argument)
        except LookupError as error:
            self.out(str(error))
            return
        if entry.uploader_id == self.node.node_id:
            self.out("that is your own file")
            return
        self.out(f"downloading {entry.name} ({format_size(entry.size)}) ...")
        threading.Thread(target=self._download_worker, args=(entry,), daemon=True).start()

    def _download_worker(self, entry) -> None:
        """Runs in the background, so you can keep chatting during a download."""
        reported = [0]

        def progress(received, total):
            quarter = received * 4 // total
            if reported[0] < quarter < 4:
                reported[0] = quarter
                self.out(f"  {entry.name}: {quarter * 25}%")

        try:
            path = self.node.files.download(entry, progress)
        except DownloadError as error:
            self.out(f"download of {entry.name} failed: {error}")
        except HandshakeError:
            self.out(f"download of {entry.name} failed: could not connect (wrong password, or the uploader is not running a node)")
        except OSError as error:
            self.out(f"download of {entry.name} failed: cannot reach the uploader ({error}). Run /get again to resume")
        else:
            self.out(f"downloaded {entry.name} to {path}")

    def _cmd_nick(self, argument):
        nickname = clean_nickname(argument)
        if nickname is None:
            self.out(f"usage: /nick <name>   (1 to {config.MAX_NICKNAME_BYTES} bytes)")
            return
        self.nickname = nickname
        if self.node is not None:
            self.node.nickname = nickname
        self.out(f"you are now {nickname}")

    def _cmd_quit(self, argument):
        self.shutdown()
        return False

    # --- chat -----------------------------------------------------------------------------

    def _send_chat(self, text: str) -> None:
        if self.node is None:
            self.out("join or create a room first (/help)")
            return
        try:
            count = self.node.send_chat(text)
        except ChatError as error:
            self.out(str(error))
            return
        self.out(f"[{clock()}] you: {sanitize(text).strip()}")
        if count == 0:
            self.out("(no peers connected: nobody received that. Use /connect)")

    def _on_chat(self, sender_id, nickname, text) -> None:
        # Called from a receiver thread. Both strings are already cleaned.
        self.out(f"[{clock()}] {nickname}: {text}")

    def _on_file(self, entry) -> None:
        self.out(f"[{clock()}] {entry.uploader_id.hex()[:8]} shared {entry.name} "
                 f"({format_size(entry.size)}). /files to list, /get to download")


# --- starting up ------------------------------------------------------------------------------

def default_nickname() -> str:
    try:
        name = clean_nickname(getpass.getuser())
    except Exception:
        name = None
    return name or "anon"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="p2pchat", description="Offline chat on the local network.")
    parser.add_argument("--nick", default=default_nickname(), help="your nickname")
    parser.add_argument("--port", type=int, default=config.MESH_PORT,
                        help="TCP port to listen on (change it to run two nodes on one machine)")
    parser.add_argument("--discovery-port", type=int, default=config.DISCOVERY_PORT,
                        help="UDP port used to find other nodes (everyone in the room must use the same one)")
    parser.add_argument("--file-port", type=int, default=config.FILE_PORT,
                        help="TCP port other nodes download your shared files from")
    parser.add_argument("--downloads", default=config.DOWNLOAD_DIR, help="folder for downloaded files")
    parser.add_argument("--host", default="0.0.0.0", help="address to listen on")
    parser.add_argument("--log", default="p2pchat.log", help="log file (the terminal stays clean)")
    parser.add_argument("--debug", action="store_true", help="log every detail")
    args = parser.parse_args(argv)

    nickname = clean_nickname(args.nick)
    if nickname is None:
        parser.error(f"--nick must be 1 to {config.MAX_NICKNAME_BYTES} bytes")

    logging.basicConfig(
        filename=args.log,
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(threadName)s %(name)s %(levelname)s %(message)s",
    )

    terminal = Terminal()
    cli = Cli(nickname, host=args.host, port=args.port, out=terminal.print,
              discovery_port=args.discovery_port, file_port=args.file_port,
              download_dir=args.downloads)
    cli.run(terminal)
    return 0