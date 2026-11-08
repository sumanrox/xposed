"""Tests for .git/config sanitization before `git checkout` runs.

The dumped .git/config is attacker-controlled: it comes from the scanned
target. `git checkout` reads it, and several keys make git execute commands.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from modules.dumper import sanitizeFile


def gitConfigGet(path, key):
    """Read a key with git's own parser. Returns None when unset."""
    proc = subprocess.run(
        ["git", "config", "--file", str(path), "--get", key],
        capture_output=True, text=True,
    )
    return proc.stdout.strip() if proc.returncode == 0 else None


def writeConfig(tmp_path, body):
    path = tmp_path / "config"
    path.write_text(body)
    return path


BASE = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
"""


class TestExecutableKeysAreNeutralized:
    """Every key git can turn into a subprocess must be inert afterwards."""

    @pytest.mark.parametrize("section,key,value", [
        ("core", "fsmonitor", "touch /tmp/pwned"),
        ("core", "hooksPath", "/tmp/evil-hooks"),
        ("core", "sshCommand", "touch /tmp/pwned"),
        ("core", "editor", "touch /tmp/pwned"),
        ("core", "pager", "touch /tmp/pwned"),
        ("core", "askpass", "touch /tmp/pwned"),
        ("core", "gitProxy", "touch /tmp/pwned"),
        ("credential", "helper", "!touch /tmp/pwned"),
        ("include", "path", "/tmp/evil-config"),
        ("gpg", "program", "touch /tmp/pwned"),
        ("uploadpack", "packObjectsHook", "touch /tmp/pwned"),
    ])
    def test_key_is_inert_after_sanitize(self, tmp_path, section, key, value):
        path = writeConfig(tmp_path, BASE + f'[{section}]\n\t{key} = {value}\n')
        sanitizeFile(str(path))
        assert gitConfigGet(path, f"{section}.{key}") is None, (
            f"{section}.{key} survived sanitization"
        )

    def test_filter_smudge_is_inert(self, tmp_path):
        """The checkout-time execution vector: .gitattributes names a filter,
        config supplies the command. Proven exploitable before this fix."""
        path = writeConfig(
            tmp_path,
            BASE + '[filter "pwn"]\n\tsmudge = sh -c \'touch /tmp/pwned\'\n\tclean = cat\n',
        )
        sanitizeFile(str(path))
        assert gitConfigGet(path, "filter.pwn.smudge") is None
        assert gitConfigGet(path, "filter.pwn.clean") is None

    def test_alias_is_inert(self, tmp_path):
        path = writeConfig(tmp_path, BASE + '[alias]\n\tco = !touch /tmp/pwned\n')
        sanitizeFile(str(path))
        assert gitConfigGet(path, "alias.co") is None

    def test_diff_textconv_is_inert(self, tmp_path):
        path = writeConfig(
            tmp_path, BASE + '[diff "evil"]\n\ttextconv = touch /tmp/pwned\n')
        sanitizeFile(str(path))
        assert gitConfigGet(path, "diff.evil.textconv") is None

    def test_key_on_the_section_header_line_is_inert(self, tmp_path):
        """git accepts the first variable on the header line."""
        path = writeConfig(tmp_path, BASE + '[core] fsmonitor = touch /tmp/pwned\n')
        sanitizeFile(str(path))
        assert gitConfigGet(path, "core.fsmonitor") is None

    def test_executable_key_after_line_one_is_inert(self, tmp_path):
        """The old regex lacked re.MULTILINE, so `^` only matched the very
        start of the file and anything below line 1 was left alone."""
        path = writeConfig(tmp_path, BASE + '\n\n[core]\n\tfsmonitor = touch /tmp/pwned\n')
        sanitizeFile(str(path))
        assert gitConfigGet(path, "core.fsmonitor") is None


class TestSafeKeysSurvive:
    """git checkout still needs to understand the repository."""

    def test_repository_format_version_survives(self, tmp_path):
        path = writeConfig(tmp_path, BASE)
        sanitizeFile(str(path))
        assert gitConfigGet(path, "core.repositoryformatversion") == "0"

    def test_bare_and_filemode_survive(self, tmp_path):
        path = writeConfig(tmp_path, BASE)
        sanitizeFile(str(path))
        assert gitConfigGet(path, "core.bare") == "false"
        assert gitConfigGet(path, "core.filemode") == "true"

    def test_object_format_survives(self, tmp_path):
        """Needed to read a sha256 repository at all."""
        path = writeConfig(
            tmp_path, BASE + "[extensions]\n\tobjectformat = sha256\n")
        sanitizeFile(str(path))
        assert gitConfigGet(path, "extensions.objectformat") == "sha256"

    def test_result_is_valid_config_for_git(self, tmp_path):
        path = writeConfig(
            tmp_path,
            BASE + '[remote "origin"]\n\turl = https://host/repo.git\n'
                   '[filter "pwn"]\n\tsmudge = touch /tmp/pwned\n',
        )
        sanitizeFile(str(path))
        proc = subprocess.run(
            ["git", "config", "--file", str(path), "--list"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0, f"git cannot parse the result: {proc.stderr}"


class TestSanitizeHygiene:
    def test_original_is_preserved_for_review(self, tmp_path):
        """The remote URL is useful intel; it must survive as inert text."""
        path = writeConfig(
            tmp_path, BASE + '[remote "origin"]\n\turl = https://host/secret-repo.git\n')
        sanitizeFile(str(path))
        assert "https://host/secret-repo.git" in path.read_text()
        assert gitConfigGet(path, "remote.origin.url") is None

    def test_no_mid_line_splicing(self, tmp_path):
        """The old regex matched 'editor'/'pager' anywhere and spliced '# '
        into the middle of unrelated values."""
        path = writeConfig(
            tmp_path, BASE + '[remote "origin"]\n\turl = https://host/editor-pager.git\n')
        sanitizeFile(str(path))
        assert "https://host/# editor" not in path.read_text()
        assert "https://host/editor-pager.git" in path.read_text()

    def test_is_idempotent(self, tmp_path):
        path = writeConfig(tmp_path, BASE + '[filter "p"]\n\tsmudge = touch /tmp/x\n')
        sanitizeFile(str(path))
        once = path.read_text()
        sanitizeFile(str(path))
        assert path.read_text() == once

    def test_missing_file_is_a_no_op(self, tmp_path):
        sanitizeFile(str(tmp_path / "absent"))

    def test_multiline_value_continuation_is_inert(self, tmp_path):
        path = writeConfig(
            tmp_path, BASE + '[filter "p"]\n\tsmudge = touch \\\n\t\t/tmp/pwned\n')
        sanitizeFile(str(path))
        assert gitConfigGet(path, "filter.p.smudge") is None


class TestCheckoutCannotExecute:
    """End-to-end: the PoC that was exploitable before this fix."""

    def test_smudge_filter_does_not_run_during_checkout(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        run = lambda *a: subprocess.run(
            a, cwd=str(repo), check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run("git", "init", "-q", ".")
        run("git", "config", "user.email", "t@example.com")
        run("git", "config", "user.name", "t")
        (repo / ".gitattributes").write_text("* filter=pwn\n")
        (repo / "app.py").write_text("original\n")
        run("git", "add", "-A")
        run("git", "commit", "-qm", "victim")
        (repo / "app.py").unlink()

        marker = tmp_path / "PWNED"
        with open(repo / ".git" / "config", "a") as f:
            f.write(f'[filter "pwn"]\n\tsmudge = sh -c \'touch {marker} && cat\'\n\tclean = cat\n')

        sanitizeFile(str(repo / ".git" / "config"))
        subprocess.run(["git", "checkout", "."], cwd=str(repo),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        assert not marker.exists(), "smudge filter executed despite sanitization"
        assert (repo / "app.py").exists(), "checkout did not restore the file"
