"""Remembers recently seen message IDs, so each packet is handled only once."""

import threading
import time
from collections import OrderedDict


class SeenCache:
    def __init__(self, max_entries: int, expiry_seconds: float, clock=time.monotonic):
        self._max_entries = max_entries
        self._expiry = expiry_seconds
        self._clock = clock   # a function that returns "now"; tests pass a fake one
        self._lock = threading.Lock()
        # message_id -> the time it was first seen.
        # An OrderedDict keeps entries in the order they were added, so the
        # OLDEST entry is always the first one.
        self._entries = OrderedDict()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def add(self, message_id: bytes) -> bool:
        """Remember message_id.

        Return True if it was new, False if we had already seen it.
        Checking and inserting happen together, under one lock.
        """
        with self._lock:
            now = self._clock()

            # 1. Remove expired entries. The oldest entry is first, so stop
            #    as soon as the first entry has not expired.
            while self._entries:
                oldest_id, added_at = next(iter(self._entries.items()))
                if now - added_at >= self._expiry:
                    del self._entries[oldest_id]
                else:
                    break

            # 2. Already seen? (A repeat does not refresh its timestamp.)
            if message_id in self._entries:
                return False

            # 3. New: store it with the time it was first seen.
            self._entries[message_id] = now

            # 4. Enforce the size cap by removing the oldest entries.
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

            # 5. It was new.
            return True


if __name__ == "__main__":
    t = [0.0]
    c = SeenCache(max_entries=2, expiry_seconds=10, clock=lambda: t[0])

    assert c.add(b"a") is True
    assert c.add(b"a") is False      # duplicate
    t[0] = 5
    c.add(b"b")
    c.add(b"c")
    assert len(c) == 2               # "a" evicted by the size cap
    t[0] = 20
    assert c.add(b"b") is True       # "b" expired, so it's new again
    print("all checks passed")