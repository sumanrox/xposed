"""Tests for the live findings table rendering."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

SAMPLE_ROW = (
    "[bold red]VULNERABLE[/bold red]",
    "https://victim.example.com",
    "[blue]203.0.113.7[/blue]",
    "[magenta]nginx/1.18[/magenta]",
    "[dim white]12:57:03[/dim white]",
    "[cyan]Dumping...[/cyan]",
)


def render(table, width):
    from rich.console import Console
    console = Console(width=width, file=open(os.devnull, "w"), record=True)
    console.print(table)
    return console.export_text()


class TestFindingsTable:
    """The target URL is the one field the operator cannot reconstruct from
    anything else, so it must survive at a standard terminal width."""

    @pytest.mark.parametrize("width", [80, 100, 120, 200])
    def test_target_url_is_visible(self, width):
        from xposedRepo import buildFindingsTable
        out = render(buildFindingsTable([SAMPLE_ROW]), width)
        assert "TARGET URL" in out
        assert "victim.example.com" in out

    @pytest.mark.parametrize("width", [100, 120, 200])
    def test_target_url_is_visible_with_ip_column(self, width):
        from xposedRepo import buildFindingsTable
        out = render(buildFindingsTable([SAMPLE_ROW], showIp=True), width)
        assert "IP ADDRESS" in out
        assert "victim.example.com" in out
        assert "203.0.113.7" in out

    def test_ip_column_omitted_by_default(self):
        from xposedRepo import buildFindingsTable
        out = render(buildFindingsTable([SAMPLE_ROW]), 120)
        assert "IP ADDRESS" not in out
        # The remaining fields must not shift out of their columns.
        assert "VULNERABLE" in out and "nginx/1.18" in out and "Dumping" in out

    def test_renders_empty_queue_without_error(self):
        from xposedRepo import buildFindingsTable
        out = render(buildFindingsTable([]), 80)
        assert "TARGET URL" in out


class TestFindingsFeed:
    """The renderer throttles redraws, so it needs a change signal that
    survives a full window -- a bounded deque's length stops changing once
    it is full, which silently froze the dashboard."""

    def test_revision_advances_even_when_window_is_full(self):
        from xposedRepo import FindingsFeed
        feed = FindingsFeed(maxlen=3)
        for i in range(8):
            feed.append((f"row{i}",))
        assert feed.revision == 8
        assert len(feed.snapshot()) == 3

    def test_snapshot_keeps_the_most_recent_findings(self):
        from xposedRepo import FindingsFeed
        feed = FindingsFeed(maxlen=2)
        for i in range(4):
            feed.append((f"row{i}",))
        assert feed.snapshot() == [("row2",), ("row3",)]

    def test_snapshot_is_a_copy(self):
        from xposedRepo import FindingsFeed
        feed = FindingsFeed(maxlen=4)
        feed.append(("a",))
        snap = feed.snapshot()
        feed.append(("b",))
        assert snap == [("a",)]

    def test_append_is_thread_safe(self):
        import threading
        from xposedRepo import FindingsFeed
        feed = FindingsFeed(maxlen=1000)

        def worker(n):
            for i in range(50):
                feed.append((n, i))

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert feed.revision == 400
        assert len(feed.snapshot()) == 400
