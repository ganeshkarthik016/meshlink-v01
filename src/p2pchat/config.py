"""All tunable numbers in one place.

Nothing else in the project should hard-code a number like a TTL or a size.
If you want to change behaviour, change it here.
"""

# --- Protocol -------------------------------------------------------------
PROTOCOL_VERSION = 1

# Field sizes in bytes (these define the packet header layout)
MESSAGE_ID_SIZE = 16   # random ID, used to detect duplicates
SENDER_ID_SIZE = 8     # node ID of whoever created the packet
NONCE_SIZE = 12        # random value needed by ChaCha20-Poly1305
HANDSHAKE_NONCE_SIZE = 16   # fresh random value each side sends in the handshake

# --- Flooding -------------------------------------------------------------
INITIAL_TTL = 5        # a packet sent with TTL n reaches n hops

# --- Limits ---------------------------------------------------------------
MAX_CHAT_TEXT = 1024       # bytes of chat text
MAX_NICKNAME_BYTES = 32
MAX_PAYLOAD_SIZE = 2048    # largest encrypted payload in a flooded packet
MAX_FILE_NAME_BYTES = 100
MAX_FILE_SIZE = 100 * 1024 * 1024   # 100 MiB
CHUNK_SIZE = 64 * 1024              # 64 KiB per file chunk
MAX_FRAME_SIZE = CHUNK_SIZE + 1024  # biggest frame we accept on any TCP link

# --- Peers ----------------------------------------------------------------
PEER_TARGET = 3        # a joining node connects until it has this many peers
PEER_MAX = 8           # a node at this many peers stops answering discovery

# --- Duplicate suppression ------------------------------------------------
SEEN_EXPIRY_SECONDS = 10 * 60
SEEN_MAX_ENTRIES = 10_000

# --- Timeouts (seconds) ---------------------------------------------------
HANDSHAKE_TIMEOUT = 10
CHUNK_TIMEOUT = 60     # long on purpose: the lab Wi-Fi is slow

# --- Password and keys ----------------------------------------------------
MIN_PASSWORD_LENGTH = 8
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024   # hashlib.scrypt raises an error without this

# --- Ports (change if they clash with something on your machine) ----------
DISCOVERY_PORT = 50001   # UDP
MESH_PORT = 50002        # TCP, chat links between peers
FILE_PORT = 50003        # TCP, file downloads