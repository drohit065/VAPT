"""OWASP ZAP integration: crawl + passive scan, optional active scan, OpenAPI import.

ZAP runs as its own container on a network shared only with the worker (it cannot reach the
database). Every scan starts a fresh ZAP session with a context limited to the validated target
hosts; spidering and active scanning are restricted to that scope. Authentication headers are
added with replacer rules that are removed again when the scan ends.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from ..normalize import make_finding, mask_assignments

ZAP_URL = os.environ.get("ZAP_URL", "http://zap:8090")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")

RISK = {"High": "High", "Medium": "Medium", "Low": "Low"}
# High-risk ZAP rules that mean remote code execution, injection or file disclosure.
CRITICAL_RULES = {"40018", "40019", "40020", "40021", "40022", "40024", "40027", "90019", "90020",
                  "6", "7", "40043", "40045", "40046", "90023", "90037"}
# Passive rules that the built-in web checks already report (avoid duplicate findings).
COVERED_BY_WEB = {"10038", "10020", "10021", "10035", "10036", "10037", "10010", "10011", "10054",
                  "10098", "10055", "10063", "90004"}


class ZapError(Exception):
    pass


class Zap:
    def __init__(self, base: str = ZAP_URL, key: str = ZAP_API_KEY, timeout: float = 60):
        if not key:
            raise ZapError("ZAP_API_KEY is not set on the server; the ZAP checks are unavailable.")
        self.base, self.key, self.timeout = base.rstrip("/"), key, timeout

    def call(self, component: str, kind: str, operation: str, /, **params) -> dict:
        """POST so that values (e.g. auth headers) never appear in URLs or ZAP's access log.
        Positional-only so that ZAP parameters such as 'name' never clash with ours."""
        url = f"{self.base}/JSON/{component}/{kind}/{operation}/"
        data = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}).encode()
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"X-ZAP-API-Key": self.key,
                                              "Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8", "replace") or "{}")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")[:300]
            raise ZapError(f"ZAP API {component}/{operation} failed: HTTP {e.code} {body}")
        except (urllib.error.URLError, OSError) as e:
            raise ZapError(f"Cannot reach ZAP at {self.base}: {e}")

    def wait_ready(self, seconds: float = 120) -> str:
        end = time.monotonic() + seconds
        last = None
        while time.monotonic() < end:
            try:
                return self.call("core", "view", "version").get("version", "?")
            except ZapError as e:
                last = e
                time.sleep(3)
        raise ZapError(f"ZAP did not become ready: {last}")


def _scope_regex(netloc: str) -> str:
    return rf"^https?://{re.escape(netloc)}(/.*)?$"


def _poll(fn, time_left, limit: float, interval: float = 5) -> bool:
    """Wait until fn() returns True; False when the time is up."""
    end = time.monotonic() + limit
    while True:
        if fn():
            return True
        if time.monotonic() > end or time_left() < 20:
            return False
        time.sleep(interval)


def alerts_to_findings(alerts: list[dict], skip_covered: bool) -> list[dict]:
    """Group ZAP alerts per rule and site into findings (pure; unit tested)."""
    groups: dict[tuple, list[dict]] = {}
    for a in alerts:
        risk = a.get("risk")
        if risk not in RISK or a.get("confidence") == "False Positive":
            continue
        rule = str(a.get("pluginId") or a.get("alertRef") or "")
        if skip_covered and rule in COVERED_BY_WEB:
            continue
        p = urllib.parse.urlsplit(a.get("url") or "")
        origin = f"{p.scheme}://{p.netloc}" if p.netloc else (a.get("url") or "")
        groups.setdefault((rule, origin), []).append(a)

    out = []
    for (rule, origin), items in groups.items():
        a = items[0]
        sev = RISK[a["risk"]]
        if sev == "High" and rule.split("-")[0] in CRITICAL_RULES and \
                any(x.get("confidence") in ("High", "Confirmed") for x in items):
            sev = "Critical"
        lines = []
        for x in items[:10]:
            line = f"{x.get('method') or 'GET'} {x.get('url')}"
            if x.get("param"):
                line += f"  param={x['param']}"
            if x.get("attack"):
                line += f"  attack={str(x['attack'])[:120]}"
            if x.get("evidence"):
                line += f"\n    evidence: {str(x['evidence'])[:200]}"
            lines.append(line)
        if len(items) > 10:
            lines.append(f"... and {len(items) - 10} more location(s)")
        cwe = f"CWE-{a['cweid']}" if str(a.get("cweid") or "").isdigit() and a["cweid"] not in ("0", "-1") else None
        refs = [r for r in (a.get("reference") or "").splitlines() if r.strip()][:5]
        desc = (a.get("description") or "").strip()
        if a.get("other"):
            desc += "\n\n" + str(a["other"]).strip()[:1000]
        desc += f"\n\nConfidence: {a.get('confidence') or 'n/a'}. Found at {len(items)} location(s)."
        if refs:
            desc += "\n\nReferences:\n" + "\n".join(f"- {r}" for r in refs)
        out.append(make_finding(
            severity=sev, title=a.get("alert") or a.get("name") or "ZAP alert", file_path=origin, line=None,
            snippet=mask_assignments("\n".join(lines)), description=desc, check="zap", scanner="zap",
            rule_id=f"zap.{rule}" if rule else None, cwe=cwe, recommendation=(a.get("solution") or "").strip(),
        ))
    return out


def run(targets: list[str], specs: list[str], auth: dict | None, active: bool, time_left,
        skip_covered: bool, scan_id: int) -> tuple[list[dict], str, list[str]]:
    """Returns (findings, detail, notes)."""
    zap = Zap()
    version = zap.wait_ready()
    notes: list[str] = []
    rule_ids: list[str] = []
    zap.call("core", "action", "newSession", name=f"vapt-scan-{scan_id}", overwrite="true")
    ctx = f"vapt-{scan_id}"
    ctx_id = zap.call("context", "action", "newContext", contextName=ctx).get("contextId")
    netlocs = sorted({urllib.parse.urlsplit(t).netloc for t in targets})
    for n in netlocs:
        zap.call("context", "action", "includeInContext", contextName=ctx, regex=_scope_regex(n))
    zap.call("spider", "action", "setOptionMaxDuration", Integer="5")
    zap.call("spider", "action", "setOptionMaxDepth", Integer="5")
    zap.call("spider", "action", "setOptionThreadCount", Integer="4")
    zap.call("ascan", "action", "setOptionThreadPerHost", Integer="2")
    zap.call("ascan", "action", "setOptionMaxScanDurationInMins",
             Integer=str(max(1, min(20, int((time_left() - 60) // 60)))))
    try:
        for i, (name, value) in enumerate((auth or {}).items()):
            rid = f"vapt-auth-{scan_id}-{i}"
            zap.call("replacer", "action", "addRule", description=rid, enabled="true", matchType="REQ_HEADER",
                     matchRegex="false", matchString=name, replacement=value, initiators="")
            rule_ids.append(rid)

        imported = 0
        for spec in specs:
            host = urllib.parse.urlsplit(spec).netloc
            try:
                r = zap.call("openapi", "action", "importUrl", url=spec, hostOverride=host, contextId=ctx_id)
                warnings = r.get("importUrl") if isinstance(r.get("importUrl"), list) else []
                imported += 1
                if warnings:
                    notes.append(f"OpenAPI import of {spec} reported {len(warnings)} warning(s).")
            except ZapError as e:
                notes.append(f"OpenAPI import of {spec} failed: {str(e)[:200]}")

        for t in targets:
            if time_left() < 60:
                notes.append("ZAP crawl stopped at the time limit.")
                break
            sid = zap.call("spider", "action", "scan", url=t, contextName=ctx, recurse="true").get("scan")
            _poll(lambda: int(zap.call("spider", "view", "status", scanId=sid).get("status", 0)) >= 100,
                  time_left, 330)
            zap.call("spider", "action", "stop", scanId=sid)
        _poll(lambda: int(zap.call("pscan", "view", "recordsToScan").get("recordsToScan", 0)) == 0, time_left, 180)

        if active:
            for n in netlocs:
                if time_left() < 120:
                    notes.append("ZAP active scan skipped for remaining hosts: time limit.")
                    break
                start = next(t for t in targets if urllib.parse.urlsplit(t).netloc == n)
                aid = zap.call("ascan", "action", "scan", url=start, recurse="true", inScopeOnly="true",
                               contextId=ctx_id).get("scan")
                done = _poll(lambda: int(zap.call("ascan", "view", "status", scanId=aid).get("status", 0)) >= 100,
                             time_left, max(60, time_left() - 90), interval=10)
                if not done:
                    zap.call("ascan", "action", "stop", scanId=aid)
                    notes.append(f"ZAP active scan of {n} stopped at the time limit; results are partial.")

        alerts: list[dict] = []
        for n in netlocs:
            for scheme in ("https", "http"):
                start = 0
                while True:
                    page = zap.call("core", "view", "alerts", baseurl=f"{scheme}://{n}", start=str(start),
                                    count="500").get("alerts", [])
                    alerts += page
                    if len(page) < 500 or len(alerts) > 20000:
                        break
                    start += 500
        urls = int(zap.call("core", "view", "numberOfMessages", baseurl="").get("numberOfMessages", 0) or 0)
    finally:
        for rid in rule_ids:
            try:
                zap.call("replacer", "action", "removeRule", description=rid)
            except ZapError:
                pass
        try:
            zap.call("core", "action", "newSession", name="vapt-idle", overwrite="true")
        except ZapError:
            pass

    findings = alerts_to_findings(alerts, skip_covered)
    detail = (f"{len(findings)} issue(s) from {len(alerts)} alert(s); {urls} request(s)"
              + (f"; {imported} OpenAPI spec(s) imported" if specs else "")
              + ("; active scan" if active else "; passive only") + f" (ZAP {version})")
    return findings, detail, notes
