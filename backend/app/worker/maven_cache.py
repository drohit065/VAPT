"""Persistent Maven POM cache for Trivy.

To know a Maven project's dependency versions, Trivy needs the parent POMs, imported BOMs and the
POM of every dependency. Fetched from Maven Central on every scan, those downloads are rate limited
(HTTP 429) and Trivy then silently reports fewer packages.

Instead, Trivy runs offline against a local repository that all scans share ($HOME/.m2/repository
points to CACHE/m2/repository). Its log names each POM it could not find; those are downloaded once
(public mirror first, then Maven Central, politely) and Trivy runs again, until nothing new is found.
Only public artifact coordinates are requested; nothing from the scanned project is sent.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.request

MIRRORS = [m.rstrip("/") for m in os.environ.get(
    "VAPT_MAVEN_MIRRORS",
    "https://maven-central.storage-download.googleapis.com/maven2,https://repo.maven.apache.org/maven2",
).split(",") if m.strip()]
MAX_POM_BYTES = 5_000_000
MISSING_TTL = 7 * 24 * 3600      # remember "not published" for a week
USER_AGENT = "vapt-scanner (maven pom cache)"

_PART = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*$")
# "g:a:v was not found in local/remote repositories" anywhere in Trivy's debug log
NOT_FOUND = re.compile(r"([A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+) was not found in local/remote")


def repo_dir(cache_dir: str) -> str:
    path = os.path.join(cache_dir, "m2", "repository")
    os.makedirs(path, exist_ok=True)
    return path


def link_home(home: str, cache_dir: str) -> str:
    """Point the scan's $HOME/.m2/repository at the shared cache (Trivy reads it from there)."""
    repo = repo_dir(cache_dir)
    m2 = os.path.join(home, ".m2")
    os.makedirs(m2, exist_ok=True)
    link = os.path.join(m2, "repository")
    if not os.path.lexists(link):
        os.symlink(repo, link)
    return repo


def pom_path(coords: str) -> str | None:
    """'org.springframework.boot:spring-boot-starter-parent:3.2.2' -> relative POM path, or None if
    the coordinates are not plain names (never a path that could leave the repository)."""
    parts = coords.split(":")
    if len(parts) != 3 or not all(_PART.match(p) and ".." not in p for p in parts):
        return None
    g, a, v = parts
    return "/".join(g.split(".") + [a, v, f"{a}-{v}.pom"])


def missing_poms(log: str) -> list[str]:
    return sorted(set(NOT_FOUND.findall(log or "")))


class PomCache:
    def __init__(self, cache_dir: str):
        self.repo = repo_dir(cache_dir)
        self._missing_file = os.path.join(cache_dir, "m2", "missing.json")
        try:
            with open(self._missing_file) as fh:
                self.missing = {k: v for k, v in json.load(fh).items() if time.time() - v < MISSING_TTL}
        except (OSError, ValueError):
            self.missing = {}
        self.downloaded = 0
        self.failed: list[str] = []

    def has(self, rel: str) -> bool:
        return os.path.isfile(os.path.join(self.repo, rel))

    def _get(self, url: str) -> bytes | None:
        """Body on 200; None on 404; raises on anything else (rate limit, network)."""
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                body = r.read(MAX_POM_BYTES + 1)
        except urllib.error.HTTPError as e:
            if e.code in (403, 404):
                return None
            raise
        if len(body) > MAX_POM_BYTES or b"<project" not in body[:4096]:
            raise ValueError("not a POM file")
        return body

    def fetch(self, coords: str, deadline: float) -> bool:
        """Download one POM into the cache. True if it is (now) cached."""
        rel = pom_path(coords)
        if not rel:
            return False
        if self.has(rel):
            return True
        if coords in self.missing:
            return False
        not_found = 0
        for mirror in MIRRORS:
            for attempt in range(3):
                if time.monotonic() > deadline:
                    self.failed.append(coords)
                    return False
                try:
                    body = self._get(f"{mirror}/{rel}")
                except (urllib.error.URLError, OSError, ValueError):
                    time.sleep(min(2 ** attempt, 8))  # rate limited or network error: back off, retry
                    continue
                if body is None:
                    not_found += 1
                    break
                dest = os.path.join(self.repo, rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                fd, tmp = tempfile.mkstemp(dir=os.path.dirname(dest), suffix=".part")
                with os.fdopen(fd, "wb") as fh:
                    fh.write(body)
                os.replace(tmp, dest)
                self.downloaded += 1
                return True
        if not_found == len(MIRRORS):  # published nowhere (e.g. a private artifact): remember it
            self.missing[coords] = time.time()
        else:
            self.failed.append(coords)
        return False

    def save(self) -> None:
        try:
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self._missing_file), suffix=".part")
            with os.fdopen(fd, "w") as fh:
                json.dump(self.missing, fh)
            os.replace(tmp, self._missing_file)
        except OSError:
            pass
