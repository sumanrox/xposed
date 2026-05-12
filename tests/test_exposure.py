"""Tests for checkGitExposure scanner logic."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import MagicMock
from xposedRepo import checkGitExposure, VULN, SUSPICIOUS, OK, ERROR


class FakeResponse:
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    def close(self):
        pass


class TestCheckGitExposure:
    """Scanner probes should correctly identify exposed .git directories."""

    def test_vulnerable_on_git_directory_listing(self):
        session = MagicMock()
        session.get.side_effect = [
            FakeResponse(200, "<html><head><title>Index of /.git</title></head></html>", {"Server": "nginx/1.18"}),
        ]
        result = checkGitExposure(session, "https://victim.com", 5.0)
        assert result == (VULN, "200", "https://victim.com", "nginx/1.18")

    def test_vulnerable_on_git_head(self):
        session = MagicMock()
        session.get.side_effect = [
            FakeResponse(404, "Not Found"),
            FakeResponse(200, "ref: refs/heads/main\n", {"Server": "Apache"}),
        ]
        result = checkGitExposure(session, "https://victim.com", 5.0)
        assert result == (VULN, "200", "https://victim.com", "Apache")

    def test_vulnerable_on_git_config(self):
        session = MagicMock()
        session.get.side_effect = [
            FakeResponse(404, "Not Found"),
            FakeResponse(404, "Not Found"),
            FakeResponse(200, "[core]\n    repositoryformatversion = 0\n", {"Server": "nginx"}),
        ]
        result = checkGitExposure(session, "https://victim.com", 5.0)
        assert result == (VULN, "200", "https://victim.com", "nginx")

    def test_suspicious_on_sha_like_head(self):
        session = MagicMock()
        session.get.side_effect = [
            FakeResponse(404, "Not Found"),
            FakeResponse(200, "a1b2c3d4e5f6", {"Server": "cloudflare"}),
        ]
        result = checkGitExposure(session, "https://suspicious.com", 5.0)
        assert result[0] == SUSPICIOUS
        assert result[2] == "https://suspicious.com"

    def test_ok_when_nothing_found(self):
        session = MagicMock()
        session.get.side_effect = [
            FakeResponse(404, "Not Found"),
            FakeResponse(404, "Not Found"),
            FakeResponse(404, "Not Found"),
            FakeResponse(404, "Not Found"),
            FakeResponse(404, "Not Found"),
        ]
        result = checkGitExposure(session, "https://safe.com", 5.0)
        assert result[0] == OK
        assert result[2] == "https://safe.com"

    def test_error_on_network_failure(self):
        import requests
        session = MagicMock()
        session.get.side_effect = requests.ConnectionError("Connection refused")
        result = checkGitExposure(session, "https://down.com", 5.0)
        assert result[0] == ERROR
        assert result[2] == "https://down.com"
