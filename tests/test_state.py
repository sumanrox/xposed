"""Tests for state file persistence, dedup store, and CSV export."""
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from xposedRepo import loadState, appendState, writeFinalCsv, DedupStore, VULN, SUSPICIOUS, OK, ERROR


@pytest.fixture
def fresh_dedup(tmp_path):
    db = str(tmp_path / "dedup.db")
    return DedupStore(db_path=db)


class TestDedupStore:
    """SQLite-backed dedup should track URLs across sessions."""

    def test_has_returns_false_for_unseen_url(self, fresh_dedup):
        assert fresh_dedup.has("https://new.com") is False

    def test_has_returns_true_after_add(self, fresh_dedup):
        fresh_dedup.add("https://new.com")
        assert fresh_dedup.has("https://new.com") is True

    def test_multiple_urls_all_trackable(self, fresh_dedup):
        urls = ["https://a.com", "https://b.com", "https://c.com"]
        for u in urls:
            fresh_dedup.add(u)
        for u in urls:
            assert fresh_dedup.has(u) is True
        assert fresh_dedup.has("https://z.com") is False

    def test_persists_across_reopen(self, tmp_path):
        db = str(tmp_path / "persist.db")
        d1 = DedupStore(db_path=db)
        d1.add("https://old.com")
        d1.close()

        d2 = DedupStore(db_path=db)
        assert d2.has("https://old.com") is True
        assert d2.has("https://new.com") is False
        d2.close()

    def test_add_many_bulk_insert(self, fresh_dedup):
        urls = [f"https://site{i}.com" for i in range(1000)]
        fresh_dedup.add_many(urls)
        for u in urls:
            assert fresh_dedup.has(u) is True


class TestLoadState:
    """State files should be parsed and resumed into dedup store."""

    def test_loads_existing_state(self, tmp_path, fresh_dedup):
        stateFile = str(tmp_path / "test.state")
        with open(stateFile, "w") as f:
            f.write("VULNERABLE,200,https://victim.com\n")
            f.write("SUSPICIOUS,403,https://suspicious.org\n")
            f.write("OK,404,https://safe.com\n")

        loadState(stateFile, fresh_dedup)
        assert fresh_dedup.has("https://victim.com")
        assert fresh_dedup.has("https://suspicious.org")
        assert fresh_dedup.has("https://safe.com")

    def test_handles_missing_file_gracefully(self, tmp_path, fresh_dedup):
        stateFile = str(tmp_path / "missing.state")
        loadState(stateFile, fresh_dedup)
        assert fresh_dedup.has("https://any.com") is False

    def test_skips_malformed_lines(self, tmp_path, fresh_dedup):
        stateFile = str(tmp_path / "bad.state")
        with open(stateFile, "w") as f:
            f.write("VULNERABLE,200,https://ok.com\n")
            f.write("bad_line_no_commas\n")
            f.write("\n")

        loadState(stateFile, fresh_dedup)
        assert fresh_dedup.has("https://ok.com")


class TestAppendState:
    """Appending to state should be thread-safe and update dedup."""

    def test_appends_to_file(self, tmp_path, fresh_dedup):
        stateFile = str(tmp_path / "append.state")
        open(stateFile, "a").close()
        appendState(stateFile, fresh_dedup, VULN, "200", "https://victim.com")

        with open(stateFile, "r") as f:
            lines = f.readlines()
        assert lines == ["VULNERABLE,200,https://victim.com\n"]

    def test_tracks_in_dedup_store(self, tmp_path, fresh_dedup):
        stateFile = str(tmp_path / "track.state")
        open(stateFile, "a").close()
        appendState(stateFile, fresh_dedup, OK, "404", "https://safe.com")
        assert fresh_dedup.has("https://safe.com")


class TestWriteFinalCsv:
    """CSV export should include all state entries."""

    def test_writes_csv_from_state(self, tmp_path):
        stateFile = str(tmp_path / "csv.state")
        with open(stateFile, "w") as f:
            f.write("VULNERABLE,200,https://victim.com\n")
            f.write("OK,404,https://safe.com\n")

        os.chdir(tmp_path)
        import xposedRepo
        orig_month_map = xposedRepo.MONTH_MAP.copy()
        try:
            xposedRepo.MONTH_MAP = {1: "Jan"}
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
            os.chdir("/home/spectre/Hacking/01-Tools/testing/dnsx/xposed")
