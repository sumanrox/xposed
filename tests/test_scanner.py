"""Tests for scanner core logic."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xposedRepo import normalizeUrl


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

    def test_rejects_wildcard_domain(self):
        assert normalizeUrl("*.example.com") is None

    def test_rejects_wildcard_with_scheme(self):
        assert normalizeUrl("https://*.example.com") is None
