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
