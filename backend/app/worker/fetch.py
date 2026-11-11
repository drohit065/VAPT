"""Fetch source code into a per-scan temporary folder. Read-only: nothing here builds or runs it."""
import os
import shutil
import stat
import subprocess
import zipfile

from ..config import get_settings
from ..security import assert_public_host, scrub, validate_branch, validate_git_url

ASKPASS = os.path.join(os.path.dirname(__file__), "askpass.sh")


class FetchError(Exception):
    pass


def _dir_size(path: str, limit: int) -> int:
    total = 0
    for dirpath, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                pass
            if total > limit:
                return total
    return total


def git_env(home: str, token: str | None) -> dict:
    """Minimal environment for git: no inherited secrets, no prompts, no system config."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": home,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_ASKPASS": ASKPASS,
    }
    for k in ("SSL_CERT_FILE", "GIT_SSL_CAINFO", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    if token:
        env["VAPT_GIT_TOKEN"] = token
    return env


GIT_SAFE_OPTS = [
    "-c", "protocol.allow=never",
    "-c", "protocol.https.allow=always",
    "-c", "http.followRedirects=false",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "credential.helper=",
    "-c", "submodule.recurse=false",
]


def clone(url: str, branch: str | None, token: str | None, dest: str, home: str, timeout: int) -> dict:
    s = get_settings()
    url = validate_git_url(url)
    branch = validate_branch(branch)
    assert_public_host(url)  # re-check at clone time (DNS can change after submission)

    cmd = ["git", *GIT_SAFE_OPTS, "clone", "--single-branch", "--no-tags", "--no-recurse-submodules"]
    if branch:
        cmd += ["--branch", branch]
    cmd += ["--", url, dest]
    try:
        proc = subprocess.run(cmd, env=git_env(home, token), capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise FetchError("Cloning timed out.")
    if proc.returncode != 0:
        msg = scrub(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "git clone failed", token)
        if "Authentication failed" in proc.stderr or "could not read Username" in proc.stderr:
            msg = "Authentication failed. Check the repository URL and access token."
        elif "not found in upstream" in proc.stderr or "Remote branch" in proc.stderr:
            msg = f"Branch '{branch}' was not found."
        raise FetchError(msg)

    limit = s.max_repo_mb * 1024 * 1024
    if _dir_size(dest, limit) > limit:
        raise FetchError(f"Repository is larger than {s.max_repo_mb} MB.")

    def git(*args):
        r = subprocess.run(["git", *GIT_SAFE_OPTS, "-C", dest, *args], env=git_env(home, None),
                           capture_output=True, text=True, timeout=60)
        return r.stdout.strip()

    return {"commit": git("rev-parse", "HEAD") or None,
            "branch": branch or git("rev-parse", "--abbrev-ref", "HEAD") or None}


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(info.external_attr >> 16)


def safe_member_path(name: str) -> str | None:
    """Return a safe relative path for a zip member, or None to skip it.

    Rejects absolute paths, drive letters and '..' (zip slip). Skips any .git component so
    an uploaded archive cannot plant a malicious .git/config that git-aware tools would obey.
    """
    name = name.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise FetchError(f"Archive contains an absolute path: {name[:100]}")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise FetchError(f"Archive contains a path traversal entry: {name[:100]}")
    if any(p.lower() == ".git" for p in parts):
        return None
    if any("\x00" in p for p in parts):
        raise FetchError("Archive contains an invalid file name.")
    return "/".join(parts) if parts else None


def extract_zip(zip_path: str, dest: str) -> dict:
    s = get_settings()
    max_bytes = s.max_extract_mb * 1024 * 1024
    max_files = s.max_extract_files
    base = os.path.realpath(dest)
    total = 0
    files = 0
    skipped_links = 0
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile:
        raise FetchError("The upload is not a valid zip archive.")
    with zf:
        infos = zf.infolist()
        if len(infos) > max_files * 2:
            raise FetchError(f"Archive has too many entries (limit {max_files} files).")
        # Cheap pre-check using declared sizes; real bytes are counted again while writing.
        if sum(i.file_size for i in infos) > max_bytes:
            raise FetchError(f"Archive expands to more than {s.max_extract_mb} MB.")
        for info in infos:
            rel = safe_member_path(info.filename)
            if rel is None:
                continue
            if _is_symlink(info):
                skipped_links += 1
                continue
            target = os.path.realpath(os.path.join(base, rel))
            if target != base and not target.startswith(base + os.sep):
                raise FetchError(f"Archive entry escapes the extraction folder: {info.filename[:100]}")
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            files += 1
            if files > max_files:
                raise FetchError(f"Archive has more than {max_files} files.")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if info.flag_bits & 0x1:
                raise FetchError("Encrypted zip archives are not supported.")
            with zf.open(info) as src, open(target, "xb") as out:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise FetchError(f"Archive expands to more than {s.max_extract_mb} MB.")
                    out.write(chunk)
            os.chmod(target, 0o640)  # never executable
    return {"files": files, "bytes": total, "skipped_symlinks": skipped_links}


def single_top_dir(path: str) -> str:
    """Zips often wrap everything in one folder; scan from inside it so paths read nicely."""
    entries = [e for e in os.listdir(path) if e not in ("__MACOSX",)]
    if len(entries) == 1:
        inner = os.path.join(path, entries[0])
        if os.path.isdir(inner) and not os.path.islink(inner):
            return inner
    return path


def remove_tree(path: str | None) -> None:
    if path and os.path.exists(path):
        shutil.rmtree(path, ignore_errors=True)
