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

    def test_writes_csv_from_state(self, tmp_path, monkeypatch):
        stateFile = str(tmp_path / "csv.state")
        with open(stateFile, "w") as f:
            f.write("VULNERABLE,200,https://victim.com\n")
            f.write("OK,404,https://safe.com\n")

        monkeypatch.chdir(tmp_path)
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


class TestStateRoundTripWithCommas:
    """Field 2 carries str(exception), which routinely contains commas.
    The URL must survive a write -> reload -> CSV round trip regardless."""

    def test_url_survives_reload_when_message_has_commas(self, tmp_path, fresh_dedup):
        stateFile = str(tmp_path / "commas.state")
        open(stateFile, "a").close()
        msg = ("HTTPSConnectionPool(host='127.0.0.1', port=9999): "
               "Max retries exceeded with url: /.git/, giving up")
        appendState(stateFile, fresh_dedup, ERROR, msg, "https://target.com")

        reloaded = DedupStore(db_path=str(tmp_path / "reload.db"))
        loadState(stateFile, reloaded)
        try:
            assert reloaded.has("https://target.com") is True
        finally:
            reloaded.close()

    def test_csv_keeps_url_in_url_column_when_message_has_commas(self, tmp_path, fresh_dedup, monkeypatch):
        import csv
        stateFile = str(tmp_path / "csv_commas.state")
        open(stateFile, "a").close()
        msg = "connection aborted, remote end closed, retrying"
        appendState(stateFile, fresh_dedup, ERROR, msg, "https://target.com")

        monkeypatch.chdir(tmp_path)
        writeFinalCsv(stateFile, outPrefix="Commas")
        csvPath = [f for f in os.listdir(tmp_path) if f.endswith("-Commas.csv")][0]
        with open(csvPath, newline="") as f:
            rows = list(csv.reader(f))

        assert rows[0] == ["status", "code_or_message", "url"]
        assert rows[1] == [ERROR, msg, "https://target.com"]


class FlakyConn:
    """Wraps a sqlite connection and fails the first *failTimes* writes."""

    def __init__(self, real, failTimes):
        self._real = real
        self._failTimes = failTimes

    def executemany(self, *args, **kwargs):
        if self._failTimes > 0:
            self._failTimes -= 1
            import sqlite3
            raise sqlite3.OperationalError("database is locked")
        return self._real.executemany(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._real, name)


class TestDedupStoreFlushFailure:
    """A failed write must not be mistaken for a completed one."""

    def test_retains_urls_when_a_flush_fails(self, tmp_path):
        dbPath = str(tmp_path / "flush.db")
        d = DedupStore(db_path=dbPath, batch_size=1)
        real = d.conn
        d.conn = FlakyConn(real, failTimes=1)
        d.add("https://victim.com")   # this flush fails
        d.conn = real                 # database healthy again
        d.close()                     # final flush must retry the URL

        reopened = DedupStore(db_path=dbPath)
        try:
            assert reopened.has("https://victim.com") is True
        finally:
            reopened.close()

    def test_warns_instead_of_failing_silently(self, tmp_path, capsys):
        d = DedupStore(db_path=str(tmp_path / "warn.db"), batch_size=1)
        real = d.conn
        d.conn = FlakyConn(real, failTimes=1)
        d.add("https://victim.com")
        d.conn = real
        d.close()

        assert "dedup" in capsys.readouterr().err.lower()


class TestDedupStoreConcurrency:
    """The scanner drives one DedupStore from every worker thread, so the
    store must tolerate concurrent has()/add() without SQLite misuse."""

    def _hammer(self, store, nthreads=20, perThread=400):
        import threading
        errors = []
        errorsLock = threading.Lock()

        def worker(n):
            try:
                for i in range(perThread):
                    url = f"https://host{n}-{i}.example"
                    if not store.has(url):
                        store.add(url)
            except BaseException as e:
                with errorsLock:
                    errors.append(f"{type(e).__name__}: {e}")

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(nthreads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return errors

    def test_concurrent_has_and_add_do_not_raise(self, tmp_path):
        store = DedupStore(db_path=str(tmp_path / "race.db"), batch_size=50)
        try:
            errors = self._hammer(store)
        finally:
            store.close()
        assert errors == [], f"{len(errors)} worker(s) failed: {errors[:3]}"

    def test_every_concurrently_added_url_is_recorded(self, tmp_path):
        dbPath = str(tmp_path / "race_persist.db")
        store = DedupStore(db_path=dbPath, batch_size=50)
        try:
            assert self._hammer(store, nthreads=8, perThread=100) == []
        finally:
            store.close()

        reopened = DedupStore(db_path=dbPath)
        try:
            missing = [
                f"https://host{n}-{i}.example"
                for n in range(8) for i in range(100)
                if not reopened.has(f"https://host{n}-{i}.example")
            ]
        finally:
            reopened.close()
        assert missing == [], f"{len(missing)} URLs lost, e.g. {missing[:3]}"
