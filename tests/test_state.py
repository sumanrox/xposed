"""Tests for state file persistence and CSV export."""
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from xposedRepo import loadState, appendState, writeFinalCsv, processedUrls, vulnResults, VULN, SUSPICIOUS, OK, ERROR


@pytest.fixture(autouse=True)
def clear_globals():
    """Clear mutable globals between tests."""
    processedUrls.clear()
    vulnResults.clear()
    yield
    processedUrls.clear()
    vulnResults.clear()


class TestLoadState:
    """State files should be parsed and resumed correctly."""

    def test_loads_existing_state(self, tmp_path):
        stateFile = str(tmp_path / "test.state")
        with open(stateFile, "w") as f:
            f.write("VULNERABLE,200,https://victim.com\n")
            f.write("SUSPICIOUS,403,https://suspicious.org\n")
            f.write("OK,404,https://safe.com\n")

        loadState(stateFile)
        assert "https://victim.com" in processedUrls
        assert "https://suspicious.org" in processedUrls
        assert "https://safe.com" in processedUrls
        assert (VULN, "200", "https://victim.com") in vulnResults
        assert (SUSPICIOUS, "403", "https://suspicious.org") in vulnResults

    def test_handles_missing_file_gracefully(self, tmp_path):
        stateFile = str(tmp_path / "missing.state")
        loadState(stateFile)
        assert processedUrls == set()

    def test_skips_malformed_lines(self, tmp_path):
        stateFile = str(tmp_path / "bad.state")
        with open(stateFile, "w") as f:
            f.write("VULNERABLE,200,https://ok.com\n")
            f.write("bad_line_no_commas\n")
            f.write("\n")

        loadState(stateFile)
        assert "https://ok.com" in processedUrls


class TestAppendState:
    """Appending to state should be thread-safe and durable."""

    def test_appends_to_file(self, tmp_path):
        stateFile = str(tmp_path / "append.state")
        open(stateFile, "a").close()
        appendState(stateFile, VULN, "200", "https://victim.com")

        with open(stateFile, "r") as f:
            lines = f.readlines()
        assert lines == ["VULNERABLE,200,https://victim.com\n"]

    def test_tracks_processed_urls(self, tmp_path):
        stateFile = str(tmp_path / "track.state")
        open(stateFile, "a").close()
        appendState(stateFile, OK, "404", "https://safe.com")
        assert "https://safe.com" in processedUrls


class TestWriteFinalCsv:
    """CSV export should include all state entries."""

    def test_writes_csv_from_state(self, tmp_path):
        stateFile = str(tmp_path / "csv.state")
        with open(stateFile, "w") as f:
            f.write("VULNERABLE,200,https://victim.com\n")
            f.write("OK,404,https://safe.com\n")

        csvPath = str(tmp_path / "report.csv")
        # Monkey-patch filename generation to use our path
        import xposedRepo
        orig_month_map = xposedRepo.MONTH_MAP.copy()
        try:
            xposedRepo.MONTH_MAP = {1: "Jan"}  # simplify
            # We can't easily intercept the filename, so just test the helper logic
            # by calling writeFinalCsv and checking the generated file in tmp_path
            os.chdir(tmp_path)
            writeFinalCsv(stateFile, outPrefix="Test")
            files = os.listdir(tmp_path)
            csv_files = [f for f in files if f.endswith("-Test.csv")]
            assert len(csv_files) == 1
            with open(csv_files[0], "r") as f:
                content = f.read()
            assert "status,code_or_message,url" in content
            assert "VULNERABLE,200,https://victim.com" in content
            assert "OK,404,https://safe.com" in content
        finally:
            xposedRepo.MONTH_MAP = orig_month_map
            os.chdir("/home/spectre/Downloads/99-Temp/xposed")
