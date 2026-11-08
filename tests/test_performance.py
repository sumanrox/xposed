"""Tests for performance-critical modules: DedupStore, TokenBucket, stream_targets."""
import sys
import os
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from xposedRepo import DedupStore, TokenBucket, stream_targets


class TestTokenBucket:
    """Token bucket should throttle requests to target rate."""

    def test_no_block_when_tokens_available(self):
        tb = TokenBucket(rate=1000)
        start = time.monotonic()
        tb.take()
        assert time.monotonic() - start < 0.01

    def test_throttles_to_target_rate(self):
        rate = 10
        tb = TokenBucket(rate=rate)
        start = time.monotonic()
        for _ in range(rate + 1):
            tb.take()
        elapsed = time.monotonic() - start
        # 11th token should wait ~0.1s, so total ~0.1s+
        assert elapsed >= 0.08

    def test_thread_safe_under_contention(self):
        tb = TokenBucket(rate=100)
        counts = []
        lock = threading.Lock()

        def worker():
            for _ in range(5):
                tb.take()
            with lock:
                counts.append(1)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(counts) == 10


class TestStreamTargets:
    """stream_targets should yield unseen URLs and skip duplicates."""

    def test_yields_normalized_urls(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("example.com\nhttps://test.org/\n\n  http://old.dev  \n")

        dedup = DedupStore(db_path=str(tmp_path / "dedup.db"))
        urls = list(stream_targets(str(f), dedup))
        assert urls == ["https://example.com", "https://test.org", "http://old.dev"]
        dedup.close()

    def test_skips_already_seen_urls(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("a.com\nb.com\na.com\nc.com\n")

        dedup = DedupStore(db_path=str(tmp_path / "dedup.db"))
        # pre-seed a.com as seen
        dedup.add("https://a.com")
        urls = list(stream_targets(str(f), dedup))
        assert urls == ["https://b.com", "https://c.com"]
        dedup.close()

    def test_empty_file_yields_nothing(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        dedup = DedupStore(db_path=str(tmp_path / "dedup.db"))
        urls = list(stream_targets(str(f), dedup))
        assert urls == []
        dedup.close()


class TestCountTargets:
    """The progress bar total must match what stream_targets actually yields,
    or the scan can never reach 100%."""

    def _write(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text(
            "example.com\n"        # counts
            "\n"                   # blank, normalizeUrl rejects
            "*.wild.com\n"         # wildcard, normalizeUrl rejects
            "https://seen.com\n"   # already in dedup, stream_targets skips
            "   \n"                # whitespace only, rejected
            "http://new.dev\n"     # counts
        )
        return f

    def test_count_matches_what_stream_targets_yields(self, tmp_path):
        from xposedRepo import countTargets
        f = self._write(tmp_path)
        dedup = DedupStore(db_path=str(tmp_path / "dedup.db"))
        dedup.add("https://seen.com")
        try:
            yielded = list(stream_targets(str(f), dedup))
            assert countTargets(str(f), dedup) == len(yielded) == 2
        finally:
            dedup.close()

    def test_count_honors_max_cap(self, tmp_path):
        from xposedRepo import countTargets
        f = self._write(tmp_path)
        dedup = DedupStore(db_path=str(tmp_path / "dedup2.db"))
        try:
            assert countTargets(str(f), dedup, maxTargets=1) == 1
        finally:
            dedup.close()

    def test_count_is_zero_for_missing_file(self, tmp_path):
        from xposedRepo import countTargets
        dedup = DedupStore(db_path=str(tmp_path / "dedup3.db"))
        try:
            assert countTargets(str(tmp_path / "nope.txt"), dedup) == 0
        finally:
            dedup.close()


class TestTokenBucketRateCeiling:
    """--rate-limit is a ceiling on requests sent to third-party targets.
    Exceeding it is a scope-compliance problem, not a performance nit."""

    def test_sustained_rate_does_not_exceed_configured_limit(self):
        rate = 20
        takes = 40
        tb = TokenBucket(rate=rate)
        start = time.monotonic()
        for _ in range(takes):
            tb.take()
        elapsed = time.monotonic() - start
        # An initial burst of `rate` is free; the rest must be paced.
        floor = ((takes - rate) / rate) * 0.9
        assert elapsed >= floor, (
            f"{takes} takes at rate={rate} finished in {elapsed:.3f}s "
            f"(effective {takes / elapsed:.1f}/s), expected >= {floor:.3f}s"
        )

    def test_rate_ceiling_holds_under_thread_contention(self):
        rate = 20
        tb = TokenBucket(rate=rate)
        perThread, nthreads = 5, 8
        takes = perThread * nthreads
        start = time.monotonic()

        def worker():
            for _ in range(perThread):
                tb.take()

        threads = [threading.Thread(target=worker) for _ in range(nthreads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.monotonic() - start
        floor = ((takes - rate) / rate) * 0.9
        assert elapsed >= floor, (
            f"{takes} takes across {nthreads} threads at rate={rate} finished "
            f"in {elapsed:.3f}s (effective {takes / elapsed:.1f}/s)"
        )

    def test_does_not_hold_the_lock_while_sleeping(self):
        tb = TokenBucket(rate=2)
        for _ in range(2):
            tb.take()           # drain the initial burst

        sleeping = threading.Thread(target=tb.take)
        sleeping.start()
        time.sleep(0.1)         # the thread is now inside a throttled sleep
        try:
            acquired = tb.lock.acquire(blocking=False)
            if acquired:
                tb.lock.release()
        finally:
            sleeping.join()
        assert acquired is True, "lock held across time.sleep blocks other workers"
