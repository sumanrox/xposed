"""Tests for the repository skeleton a dump must leave on disk.

git's repository discovery requires .git/refs and .git/objects to exist as
directories, even when empty. A target whose refs are all packed into
.git/packed-refs has no loose ref files to fetch, so nothing ever creates
.git/refs and every later git invocation fails with "not a git repository".
`git gc` runs automatically, so pack-only is the common case on a real server.
"""
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


def gitOk(directory, *args):
    """Run a git command in *directory*; True when git accepts the repo."""
    proc = subprocess.run(
        ["git", *args], cwd=str(directory), capture_output=True, text=True)
    return proc.returncode == 0, (proc.stderr or proc.stdout).strip()


def buildPackOnlyDump(tmp_path):
    """Produce what fetchGit leaves behind for a pack-only target.

    The dumper fetches individual files, so a directory only exists if some
    fetched path created it. With refs packed there are no loose refs, hence
    no .git/refs -- which is what this reproduces.
    """
    victim = tmp_path / "victim"
    victim.mkdir()
    run = lambda *a: subprocess.run(
        a, cwd=str(victim), check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run("git", "init", "-q", ".")
    run("git", "config", "user.email", "t@example.com")
    run("git", "config", "user.name", "t")
    (victim / "app.py").write_text("print('secret')\n")
    run("git", "add", "-A")
    run("git", "commit", "-qm", "initial")
    run("git", "gc", "-q", "--prune=now")      # refs -> packed-refs
    assert (victim / ".git" / "packed-refs").exists()

    dump = tmp_path / "dump"
    dump.mkdir()
    shutil.copytree(victim / ".git", dump / ".git")
    # The dumper never creates these, because nothing it fetches lives there.
    shutil.rmtree(dump / ".git" / "refs", ignore_errors=True)
    return dump


class TestGitLayout:
    def test_pack_only_dump_is_unusable_without_the_refs_directory(self, tmp_path):
        """Characterises the bug this fix addresses."""
        dump = buildPackOnlyDump(tmp_path)
        assert not (dump / ".git" / "refs").exists()
        ok, err = gitOk(dump, "status", "--short")
        assert not ok and "not a git repository" in err.lower(), (
            f"expected git to reject the dump, got ok={ok} err={err!r}"
        )

    def test_ensure_git_layout_makes_the_dump_usable(self, tmp_path):
        from modules.dumper import ensureGitLayout
        dump = buildPackOnlyDump(tmp_path)
        ensureGitLayout(str(dump))

        ok, err = gitOk(dump, "status", "--short")
        assert ok, f"git still rejects the dump: {err}"

    def test_checkout_restores_files_after_ensure_git_layout(self, tmp_path):
        from modules.dumper import ensureGitLayout
        dump = buildPackOnlyDump(tmp_path)
        ensureGitLayout(str(dump))

        ok, err = gitOk(dump, "checkout", ".")
        assert ok, f"checkout failed: {err}"
        assert (dump / "app.py").read_text() == "print('secret')\n"

    def test_creates_objects_directory_too(self, tmp_path):
        """A target that serves HEAD but no objects leaves .git/objects absent,
        which git also rejects."""
        from modules.dumper import ensureGitLayout
        dump = tmp_path / "bare-dump"
        (dump / ".git").mkdir(parents=True)
        (dump / ".git" / "HEAD").write_text("ref: refs/heads/main\n")

        ensureGitLayout(str(dump))
        assert (dump / ".git" / "refs").is_dir()
        assert (dump / ".git" / "objects").is_dir()

    def test_is_idempotent_and_keeps_existing_contents(self, tmp_path):
        from modules.dumper import ensureGitLayout
        dump = tmp_path / "dump"
        refs = dump / ".git" / "refs" / "heads"
        refs.mkdir(parents=True)
        (refs / "main").write_text("a" * 40 + "\n")

        ensureGitLayout(str(dump))
        ensureGitLayout(str(dump))
        assert (refs / "main").read_text() == "a" * 40 + "\n"
