"""Tests for pack file object enumeration in the dumper."""
import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from modules.dumper import collectPackedObjects


def buildPackedRepo(path):
    """Create a git repo at *path* whose objects live entirely in a pack file.

    Returns the repo path. Mirrors what a dumper fetches from a target that
    serves .git/objects/pack/ but no directory listing.
    """
    path = str(path)
    os.makedirs(path, exist_ok=True)
    run = lambda *args: subprocess.run(
        args, cwd=path, check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    run("git", "init", "-q", ".")
    run("git", "config", "user.email", "t@example.com")
    run("git", "config", "user.name", "t")
    with open(os.path.join(path, "app.py"), "w") as f:
        f.write("print('hello')\n")
    run("git", "add", "-A")
    run("git", "commit", "-qm", "initial commit")
    # Pack every loose object away, as a real server-side repo would have.
    run("git", "gc", "-q", "--prune=now")
    return path


class TestCollectPackedObjects:
    """Objects inside fetched pack files must be enumerated, so the dumper
    knows which objects it already holds and which it still has to fetch."""

    def test_enumerates_objects_from_packfile(self, tmp_path):
        repo = buildPackedRepo(tmp_path / "victim")
        # Sanity: the fixture really is packed, not loose.
        packDir = os.path.join(repo, ".git", "objects", "pack")
        assert any(f.endswith(".pack") for f in os.listdir(packDir))

        packed, referenced = collectPackedObjects(repo)

        # One commit of one file packs to exactly commit + tree + blob.
        assert len(packed) == 3
        # The commit references its tree; the tree references the blob.
        assert referenced

    def test_returns_empty_sets_when_no_pack_directory(self, tmp_path):
        assert collectPackedObjects(str(tmp_path)) == (set(), set())

    def test_skips_corrupt_pack_without_raising(self, tmp_path):
        packDir = tmp_path / ".git" / "objects" / "pack"
        packDir.mkdir(parents=True)
        sha = "a" * 40
        (packDir / f"pack-{sha}.pack").write_bytes(b"not a pack")
        (packDir / f"pack-{sha}.idx").write_bytes(b"not an index")

        assert collectPackedObjects(str(tmp_path)) == (set(), set())
