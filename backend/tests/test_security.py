"""Tests for input validation that protects the scanner itself."""
import io
import os
import stat
import zipfile

import pytest

from app.security import ValidationError, scrub, validate_branch, validate_git_url
from app.worker import fetch


@pytest.mark.parametrize("url", [
    "https://github.com/org/repo",
    "https://github.com/org/repo.git",
    "https://gitlab.example.com/group/sub/repo",
])
def test_valid_urls(url):
    assert validate_git_url(url).startswith("https://")


@pytest.mark.parametrize("url", [
    "http://github.com/org/repo",
    "git@github.com:org/repo.git",
    "ssh://github.com/org/repo",
    "file:///etc/passwd",
    "https://user:pass@github.com/org/repo",
    "https://127.0.0.1/repo",
    "https://github.com/org/repo?x=1",
    "https://github.com/org/../repo",
    "https://github.com/org/repo; rm -rf /",
    "-c core.sshCommand=x https://github.com/a/b",
    "",
])
def test_invalid_urls(url):
    with pytest.raises((ValidationError, ValueError)):
        validate_git_url(url)


@pytest.mark.parametrize("branch", ["--upload-pack=x", "a..b", "a b", "x;y", "/main", "main.lock"])
def test_invalid_branches(branch):
    with pytest.raises(ValidationError):
        validate_branch(branch)


def test_valid_branch():
    assert validate_branch("feature/login-v2") == "feature/login-v2"
    assert validate_branch("") is None


def test_scrub_token():
    assert "tok123" not in scrub("fatal: https://x:tok123@github.com failed tok123", "tok123")


def _zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name)
            if mode:
                info.external_attr = mode << 16
            z.writestr(info, data)
    return buf.getvalue()


@pytest.fixture
def settings_env(monkeypatch):
    monkeypatch.setenv("MAX_EXTRACT_MB", "1")
    monkeypatch.setenv("MAX_EXTRACT_FILES", "10")
    from app.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _extract(tmp_path, entries):
    zp = tmp_path / "u.zip"
    zp.write_bytes(_zip(entries))
    dest = tmp_path / "out"
    dest.mkdir()
    return fetch.extract_zip(str(zp), str(dest)), dest


def test_zip_ok_and_skips_git_and_symlinks(tmp_path, settings_env):
    info, dest = _extract(tmp_path, [
        ("proj/app.py", b"print(1)", 0),
        ("proj/.git/config", b"[core]\nfsmonitor = evil", 0),
        ("proj/link", b"/etc/passwd", stat.S_IFLNK | 0o777),
    ])
    assert (dest / "proj/app.py").read_bytes() == b"print(1)"
    assert not (dest / "proj/.git").exists()
    assert not (dest / "proj/link").exists()
    assert info["skipped_symlinks"] == 1
    assert not os.access(dest / "proj/app.py", os.X_OK)


@pytest.mark.parametrize("name", ["../evil.py", "a/../../evil.py", "/etc/evil", "C:/evil"])
def test_zip_traversal_rejected(tmp_path, settings_env, name):
    with pytest.raises(fetch.FetchError):
        _extract(tmp_path, [(name, b"x", 0)])


def test_zip_bomb_rejected(tmp_path, settings_env):
    with pytest.raises(fetch.FetchError):
        _extract(tmp_path, [("big.txt", b"0" * (2 * 1024 * 1024), 0)])


def test_zip_too_many_files(tmp_path, settings_env):
    with pytest.raises(fetch.FetchError):
        _extract(tmp_path, [(f"f{i}.txt", b"x", 0) for i in range(11)])
