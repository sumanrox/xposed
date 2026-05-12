"""Tests for scanner core logic."""
import sys
import os
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from xposedRepo import normalizeUrl, VULN, SUSPICIOUS, OK, ERROR


class TestNormalizeUrl:
    """URL normalization should be robust and safe."""

    def test_adds_https_when_scheme_missing(self):
        assert normalizeUrl("example.com") == "https://example.com"

    def test_preserves_https(self):
        assert normalizeUrl("https://example.com") == "https://example.com"

    def test_preserves_http(self):
        assert normalizeUrl("http://example.com") == "http://example.com"

    def test_strips_trailing_slash(self):
        assert normalizeUrl("https://example.com/") == "https://example.com"

    def test_strips_whitespace(self):
        assert normalizeUrl("  example.com  ") == "https://example.com"

    def test_returns_none_for_empty_string(self):
        assert normalizeUrl("") is None

    def test_returns_none_for_whitespace_only(self):
        assert normalizeUrl("   ") is None

    def test_handles_url_with_path(self):
        assert normalizeUrl("example.com/path") == "https://example.com/path"


class TestStreamTargets:
    """Target loading should support streaming without loading all into memory."""

    def test_stream_targets_from_file(self):
        from xposedRepo import streamTargetsFromFile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("example.com\n")
            f.write("https://test.org/\n")
            f.write("\n")
            f.write("  http://old.dev  \n")
            f.write("   \n")
            path = f.name
        try:
            targets = list(streamTargetsFromFile(path))
            assert targets == [
                "https://example.com",
                "https://test.org",
                "http://old.dev",
            ]
        finally:
            os.unlink(path)

    def test_stream_targets_skips_invalid_lines(self):
        from xposedRepo import streamTargetsFromFile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("example.com\n")
            f.write("   \n")
            f.write("\n")
            path = f.name
        try:
            targets = list(streamTargetsFromFile(path))
            assert targets == ["https://example.com"]
        finally:
            os.unlink(path)

    def test_stream_targets_handles_missing_file(self):
        from xposedRepo import streamTargetsFromFile
        targets = list(streamTargetsFromFile("/nonexistent/file.txt"))
        assert targets == []


class TestBoundedExecution:
    """Scanner should process targets with bounded in-flight tasks."""

    def test_bounded_submit(self):
        from xposedRepo import boundedMap
        results = []
        lock = threading.Lock()

        def worker(x):
            time.sleep(0.01)
            with lock:
                results.append(x)
            return x * 2

        inputs = list(range(20))
        outputs = list(boundedMap(worker, inputs, maxWorkers=4, maxInflight=6))
        assert sorted(outputs) == [x * 2 for x in range(20)]
        assert len(outputs) == 20
