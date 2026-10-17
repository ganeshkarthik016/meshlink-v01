import threading

from p2pchat.seen_cache import SeenCache


class FakeClock:
    """A clock we control, so tests do not need to wait for real time."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def make_cache(max_entries=100, expiry_seconds=600):
    clock = FakeClock()
    cache = SeenCache(max_entries=max_entries, expiry_seconds=expiry_seconds, clock=clock)
    return cache, clock


A = b"a" * 16
B = b"b" * 16
C = b"c" * 16
D = b"d" * 16


def test_new_id_returns_true():
    cache, _ = make_cache()
    assert cache.add(A) is True


def test_repeated_id_returns_false():
    cache, _ = make_cache()
    cache.add(A)
    assert cache.add(A) is False


def test_different_ids_are_both_new():
    cache, _ = make_cache()
    assert cache.add(A) is True
    assert cache.add(B) is True


def test_len_counts_entries():
    cache, _ = make_cache()
    assert len(cache) == 0
    cache.add(A)
    cache.add(B)
    cache.add(A)  # duplicate, not counted twice
    assert len(cache) == 2


def test_entry_still_remembered_before_expiry():
    cache, clock = make_cache(expiry_seconds=600)
    cache.add(A)
    clock.now = 599
    assert cache.add(A) is False


def test_entry_forgotten_after_expiry():
    cache, clock = make_cache(expiry_seconds=600)
    cache.add(A)
    clock.now = 601
    assert cache.add(A) is True


def test_expired_entries_are_removed():
    cache, clock = make_cache(expiry_seconds=600)
    cache.add(A)
    cache.add(B)
    clock.now = 601
    cache.add(C)  # adding triggers the cleanup
    assert len(cache) == 1


def test_duplicate_does_not_extend_lifetime():
    cache, clock = make_cache(expiry_seconds=600)
    cache.add(A)            # first seen at t=0
    clock.now = 400
    assert cache.add(A) is False   # seen again, must NOT restart the timer
    clock.now = 601
    assert cache.add(A) is True    # 601 seconds after the first sighting


def test_oldest_entry_is_evicted_when_full():
    cache, _ = make_cache(max_entries=3)
    for message_id in (A, B, C, D):
        cache.add(message_id)
    assert len(cache) == 3
    assert cache.add(D) is False   # newest is still remembered
    assert cache.add(A) is True    # oldest was evicted, so it counts as new again


def test_only_one_thread_wins_a_race():
    # Many threads add the same ID at once. Exactly one may be told "new".
    # If add() checked and inserted in two separate steps, two threads could
    # both be told "new", and a message would be shown and forwarded twice.
    cache, _ = make_cache()
    results = []

    def worker():
        for _ in range(1000):
            results.append(cache.add(b"same-id-same-id!"))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results.count(True) == 1