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


class FakeResponseCT(FakeResponse):
    """FakeResponse with a Content-Type, for probes that must reject HTML."""

    def __init__(self, status_code, text, contentType=None, server=None):
        headers = {}
        if contentType:
            headers["Content-Type"] = contentType
        if server:
            headers["Server"] = server
        super().__init__(status_code, text, headers)


SOFT_404_HTML = (
    '<!DOCTYPE html><html><head><meta charset="utf-8">'
    '<link href="/assets/main.64f1e174.css" rel="stylesheet">'
    '<style>body{color:#1a1a1a;background:#666666}</style>'
    '</head><body>Page not found. Access denied.</body></html>'
)


class TestNoFalsePositives:
    """Observed against 300 live hosts: 22/22 SUSPICIOUS verdicts were soft-404
    HTML pages or followed redirects, none had a .git directory."""

    def test_soft_404_html_on_head_is_not_a_finding(self):
        """Asset hashes and CSS hex colours are not git object IDs."""
        session = MagicMock()
        session.get.side_effect = [
            FakeResponseCT(404, "Not Found"),
            FakeResponseCT(200, SOFT_404_HTML, "text/html", "nginx"),
            FakeResponseCT(404, "Not Found"),
            FakeResponseCT(404, "Not Found"),
            FakeResponseCT(404, "Not Found"),
        ]
        result = checkGitExposure(session, "https://acts.nhb.gov.sg", 5.0)
        assert result[0] == OK, f"soft-404 HTML reported as {result[0]}"

    def test_redirects_are_not_followed(self):
        """A redirect on every probe means no .git, whatever it points at."""
        session = MagicMock()
        session.get.side_effect = [
            FakeResponseCT(302, "", None, "nginx"),
            FakeResponseCT(302, "", None, "nginx"),
            FakeResponseCT(302, "", None, "nginx"),
            FakeResponseCT(302, "", None, "nginx"),
            FakeResponseCT(302, "", None, "nginx"),
        ]
        result = checkGitExposure(session, "https://GROAMN3REXZGWP21.ras.gov.sg", 5.0)
        assert result[0] == OK, f"302 redirect reported as {result[0]}"

    def test_probes_request_no_redirects(self):
        session = MagicMock()
        session.get.side_effect = [FakeResponseCT(404, "Not Found")] * 5
        checkGitExposure(session, "https://safe.example", 5.0)
        assert session.get.call_count >= 1
        for call in session.get.call_args_list:
            assert call.kwargs.get("allow_redirects") is False, (
                "following redirects is what turned 13 of 22 live false "
                "positives into findings"
            )

    def test_html_pack_listing_is_not_a_finding(self):
        """Content-Type: text/* on objects/pack/ matched every soft-404."""
        session = MagicMock()
        session.get.side_effect = [
            FakeResponseCT(404, "Not Found"),
            FakeResponseCT(404, "Not Found"),
            FakeResponseCT(404, "Not Found"),
            FakeResponseCT(200, SOFT_404_HTML, "text/html", "nginx"),
            FakeResponseCT(200, SOFT_404_HTML, "text/html", "nginx"),
        ]
        result = checkGitExposure(session, "https://aim-sg.caas.gov.sg", 5.0)
        assert result[0] == OK, f"HTML pack listing reported as {result[0]}"


class TestGenuineExposureStillDetected:
    """Tightening detection must not lose real findings."""

    def test_detached_head_sha_is_vulnerable(self):
        session = MagicMock()
        session.get.side_effect = [
            FakeResponseCT(404, "Not Found"),
            FakeResponseCT(200, "a" * 40 + "\n", "text/plain", "nginx"),
        ]
        result = checkGitExposure(session, "https://victim.example", 5.0)
        assert result[0] == VULN

    def test_ref_head_without_content_type_is_vulnerable(self):
        session = MagicMock()
        session.get.side_effect = [
            FakeResponseCT(404, "Not Found"),
            FakeResponseCT(200, "ref: refs/heads/main\n", None, "Apache"),
        ]
        result = checkGitExposure(session, "https://victim.example", 5.0)
        assert result[0] == VULN

    def test_real_pack_index_is_vulnerable(self):
        session = MagicMock()
        session.get.side_effect = [
            FakeResponseCT(404, "Not Found"),
            FakeResponseCT(404, "Not Found"),
            FakeResponseCT(404, "Not Found"),
            FakeResponseCT(200, "P pack-%s.pack\n" % ("b" * 40), "text/plain", "nginx"),
        ]
        result = checkGitExposure(session, "https://victim.example", 5.0)
        assert result[0] == VULN

    def test_directory_listing_is_html_and_still_vulnerable(self):
        """The /.git/ listing is legitimately HTML -- only HEAD and config
        must reject it."""
        session = MagicMock()
        session.get.side_effect = [
            FakeResponseCT(
                200,
                "<html><head><title>Index of /.git</title></head></html>",
                "text/html",
                "nginx/1.18",
            ),
        ]
        result = checkGitExposure(session, "https://victim.example", 5.0)
        assert result == (VULN, "200", "https://victim.example", "nginx/1.18")


class CountingLimiter:
    def __init__(self):
        self.takes = 0

    def take(self):
        self.takes += 1


class TestRateLimitIsPerRequest:
    """--rate-limit is documented as requests per second. Taking one token
    per target let a scan issue up to 5x the configured rate."""

    def test_one_token_per_http_request_on_the_ok_path(self):
        session = MagicMock()
        session.get.side_effect = [FakeResponseCT(404, "Not Found")] * 5
        limiter = CountingLimiter()
        checkGitExposure(session, "https://safe.example", 5.0, limiter=limiter)
        assert limiter.takes == session.get.call_count == 5

    def test_tokens_match_requests_when_finding_short_circuits(self):
        session = MagicMock()
        session.get.side_effect = [
            FakeResponseCT(404, "Not Found"),
            FakeResponseCT(200, "ref: refs/heads/main\n", None, "nginx"),
        ]
        limiter = CountingLimiter()
        result = checkGitExposure(session, "https://victim.example", 5.0, limiter=limiter)
        assert result[0] == VULN
        assert limiter.takes == session.get.call_count == 2

    def test_works_without_a_limiter(self):
        session = MagicMock()
        session.get.side_effect = [FakeResponseCT(404, "Not Found")] * 5
        assert checkGitExposure(session, "https://safe.example", 5.0)[0] == OK
