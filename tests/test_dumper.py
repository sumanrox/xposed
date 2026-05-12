"""Tests for dumper security and correctness."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


class TestIsSafePath:
    """isSafePath must prevent directory traversal relative to the output directory."""

    def test_rejects_absolute_path(self, tmp_path):
        from modules.dumper import isSafePath
        assert isSafePath("/etc/passwd", str(tmp_path)) is False

    def test_accepts_simple_relative_path(self, tmp_path):
        from modules.dumper import isSafePath
        assert isSafePath("config", str(tmp_path)) is True

    def test_rejects_parent_directory_traversal(self, tmp_path):
        from modules.dumper import isSafePath
        assert isSafePath("../etc/passwd", str(tmp_path)) is False

    def test_rejects_nested_parent_traversal(self, tmp_path):
        from modules.dumper import isSafePath
        assert isSafePath("foo/../../etc/passwd", str(tmp_path)) is False

    def test_accepts_deep_relative_path(self, tmp_path):
        from modules.dumper import isSafePath
        assert isSafePath(".git/objects/ab/cd1234", str(tmp_path)) is True

    def test_detects_escape_when_base_is_not_home(self, tmp_path):
        """Current implementation hardcodes ~; it must use the actual base dir."""
        from modules.dumper import isSafePath
        # If base is /tmp/something and path is ../outside, it should fail
        assert isSafePath("../outside", str(tmp_path)) is False
