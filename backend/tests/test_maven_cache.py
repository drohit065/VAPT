"""Persistent Maven POM cache (no network: downloads are faked)."""
import time
import urllib.error

from app.worker import maven_cache
from app.worker.maven_cache import PomCache, link_home, missing_poms, pom_path

LOG = """\
2026-11-18T05:22:10Z	DEBUG	[pom] Parent POM not found	artifact="org.springframework.boot:spring-boot-starter-parent:3.2.2" err="2 errors occurred:\\n\\t* stat /x/pom.xml: no such file or directory\\n\\t* org.springframework.boot:spring-boot-starter-parent:3.2.2 was not found in local/remote repositories\\n\\n"
2026-11-17T09:07:57Z	DEBUG	[pom] Repository error	err="io.jsonwebtoken:jjwt-api:0.11.3 was not found in local/remote repositories"
"""
POM = b'<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion></project>'


def test_missing_poms_from_trivy_log():
    assert missing_poms(LOG) == ["io.jsonwebtoken:jjwt-api:0.11.3",
                                 "org.springframework.boot:spring-boot-starter-parent:3.2.2"]


def test_pom_path_is_safe():
    assert pom_path("org.springframework.boot:spring-boot-starter-parent:3.2.2") == \
        "org/springframework/boot/spring-boot-starter-parent/3.2.2/spring-boot-starter-parent-3.2.2.pom"
    assert pom_path("..:x:1") is None and pom_path("a/b:c:1") is None and pom_path("a:b") is None


def test_link_home_points_at_shared_cache(tmp_path):
    repo = link_home(str(tmp_path / "home"), str(tmp_path / "cache"))
    link = tmp_path / "home" / ".m2" / "repository"
    assert link.is_symlink() and str(link.resolve()) == str((tmp_path / "cache" / "m2" / "repository").resolve())
    assert repo.endswith("m2/repository")


def test_fetch_uses_first_mirror_then_falls_back(tmp_path, monkeypatch):
    calls = []

    def fake_get(self, url):
        calls.append(url)
        if url.startswith("https://mirror-a"):
            raise urllib.error.HTTPError(url, 429, "Too Many Requests", {}, None)
        return POM
    monkeypatch.setattr(maven_cache, "MIRRORS", ["https://mirror-a/maven2", "https://mirror-b/maven2"])
    monkeypatch.setattr(PomCache, "_get", fake_get)
    monkeypatch.setattr(maven_cache.time, "sleep", lambda s: None)
    cache = PomCache(str(tmp_path))
    assert cache.fetch("g.x:a:1.0", time.monotonic() + 60)
    assert cache.has("g/x/a/1.0/a-1.0.pom") and cache.downloaded == 1
    assert calls[-1] == "https://mirror-b/maven2/g/x/a/1.0/a-1.0.pom"
    calls.clear()
    assert cache.fetch("g.x:a:1.0", time.monotonic() + 60) and not calls  # cached: no download


def test_not_published_is_remembered(tmp_path, monkeypatch):
    calls = []

    def fake_get(self, url):
        calls.append(url)
        return None  # 404 everywhere: a private artifact
    monkeypatch.setattr(maven_cache, "MIRRORS", ["https://m1", "https://m2"])
    monkeypatch.setattr(PomCache, "_get", fake_get)
    cache = PomCache(str(tmp_path))
    assert not cache.fetch("com.internal:lib:1", time.monotonic() + 60)
    cache.save()
    calls.clear()
    again = PomCache(str(tmp_path))
    assert not again.fetch("com.internal:lib:1", time.monotonic() + 60) and not calls
    assert not again.failed  # not published is not a download failure
