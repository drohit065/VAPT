"""Create Jira or GitHub issues from findings.

Endpoints must be https:// on a public host; requests are pinned to the validated address.
Tokens live encrypted in app settings (key "ticketing") and are never returned by the API.
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import re
import socket
import ssl
from urllib.parse import urlsplit

from .security import ValidationError, assert_public_target, validate_target_url

PROVIDERS = ("none", "jira", "github")
DEFAULTS = {"provider": "none", "jira_url": "", "jira_email": "", "jira_project": "", "jira_issue_type": "Bug",
            "github_repo": "", "labels": ["security", "vapt"]}
_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_JIRA_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,19}$")


class TicketError(Exception):
    pass


def http_json(method: str, url: str, headers: dict, payload: dict | None = None, timeout: float = 20) -> tuple[int, dict]:
    url = validate_target_url(url)
    if not url.startswith("https://"):
        raise ValidationError("Only https:// endpoints are allowed.")
    ip = assert_public_target(url)[0]
    p = urlsplit(url)

    class Pinned(http.client.HTTPSConnection):
        def connect(self):
            sock = socket.create_connection((ip, self.port), self.timeout)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)

    conn = Pinned(p.hostname, p.port or 443, timeout=timeout, context=ssl.create_default_context())
    try:
        body = json.dumps(payload).encode() if payload is not None else None
        conn.request(method, (p.path or "/") + (f"?{p.query}" if p.query else ""), body=body,
                     headers={"Accept": "application/json", "Content-Type": "application/json",
                              "User-Agent": "VAPT-Scanner/1.0", **headers})
        r = conn.getresponse()
        raw = r.read(200_000).decode("utf-8", "replace")
        try:
            data = json.loads(raw) if raw else {}
        except ValueError:
            data = {"raw": raw[:300]}
        return r.status, data
    finally:
        conn.close()


def validate_config(cfg: dict) -> None:
    if cfg["provider"] not in PROVIDERS:
        raise ValidationError("provider must be none, jira or github")
    if cfg["provider"] == "jira":
        if not cfg.get("jira_url") or not cfg.get("jira_email"):
            raise ValidationError("Enter the Jira site URL and the account email.")
        validate_target_url(cfg["jira_url"])
        if not cfg["jira_url"].startswith("https://"):
            raise ValidationError("The Jira URL must use https://")
        if not _JIRA_KEY.match(cfg.get("jira_project") or ""):
            raise ValidationError("Enter the Jira project key (e.g. SEC).")
    if cfg["provider"] == "github" and not _REPO.match(cfg.get("github_repo") or ""):
        raise ValidationError("Enter the GitHub repository as owner/name.")


def _auth(cfg: dict, secrets: dict) -> dict:
    if cfg["provider"] == "jira":
        if not secrets.get("jira_token"):
            raise TicketError("The Jira API token is not set.")
        raw = f"{cfg['jira_email']}:{secrets['jira_token']}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
    if cfg["provider"] == "github":
        if not secrets.get("github_token"):
            raise TicketError("The GitHub token is not set.")
        return {"Authorization": f"Bearer {secrets['github_token']}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"}
    raise TicketError("No ticketing provider is configured.")


def test_connection(cfg: dict, secrets: dict) -> str:
    headers = _auth(cfg, secrets)
    if cfg["provider"] == "jira":
        status, data = http_json("GET", cfg["jira_url"].rstrip("/") + f"/rest/api/2/project/{cfg['jira_project']}", headers)
        if status != 200:
            raise TicketError(f"Jira answered HTTP {status}: {str(data)[:200]}")
        return f"Connected to Jira project {data.get('key')} ({data.get('name')})."
    status, data = http_json("GET", f"https://api.github.com/repos/{cfg['github_repo']}", headers)
    if status != 200:
        raise TicketError(f"GitHub answered HTTP {status}: {data.get('message', '')}")
    if not data.get("has_issues", True):
        raise TicketError("Issues are disabled on that repository.")
    return f"Connected to GitHub repository {data.get('full_name')}."


def ticket_text(f: dict, project_name: str, scan_id: int, app_url: str) -> tuple[str, str]:
    """(title, markdown body)."""
    loc = f["file_path"] + (f":{f['line']}" if f.get("line") else "")
    title = f"[VAPT][{f['severity']}] {f['title']}"
    if len(title) + len(loc) + 3 <= 250:
        title += f" ({loc})"
    title = title[:250]
    lines = [f"**Severity:** {f['severity']}" + (f" · CVSS {f['cvss_score']:.1f}" if f.get("cvss_score") is not None else ""),
             f"**Project:** {project_name} · scan #{scan_id}",
             f"**Location:** `{loc}`"]
    if f.get("cwe"):
        lines.append(f"**CWE:** {f['cwe']}")
    if f.get("owasp"):
        lines.append(f"**OWASP:** {f['owasp']}")
    if app_url:
        lines.append(f"**Report:** {app_url.rstrip('/')}/scans/{scan_id}/report")
    body = "\n".join(lines)
    locs = [l for l in (f.get("locations") or []) if isinstance(l, dict)]
    if len(locs) > 1:
        body += f"\n\n**All locations ({len(locs)})**\n" + "\n".join(
            f"- `{l.get('file', '')}{':' + str(l['line']) if l.get('line') else ''}`" for l in locs[:100])
    if f.get("snippet"):
        body += "\n\n**Evidence**\n```\n" + f["snippet"][:3000] + "\n```"
    for label, key in (("What is wrong", "description"), ("How it could be exploited", "exploitation"),
                       ("Recommended fix", "recommendation")):
        if f.get(key):
            body += f"\n\n**{label}**\n{f[key][:4000]}"
    body += f"\n\n_Created by VAPT Scanner. Finding fingerprint: {f.get('fingerprint') or 'n/a'}_"
    return title, body


def create_issue(cfg: dict, secrets: dict, title: str, body: str) -> tuple[str, str]:
    """Returns (key, url)."""
    headers = _auth(cfg, secrets)
    labels = [re.sub(r"\s+", "-", x)[:50] for x in cfg.get("labels") or [] if x][:10]
    if cfg["provider"] == "jira":
        payload = {"fields": {"project": {"key": cfg["jira_project"]}, "summary": title[:250],
                              "issuetype": {"name": cfg.get("jira_issue_type") or "Bug"},
                              "description": body.replace("**", "*").replace("```", "{code}"), "labels": labels}}
        status, data = http_json("POST", cfg["jira_url"].rstrip("/") + "/rest/api/2/issue", headers, payload)
        if status not in (200, 201) or not data.get("key"):
            raise TicketError(f"Jira refused the issue (HTTP {status}): {str(data.get('errors') or data)[:300]}")
        return data["key"], cfg["jira_url"].rstrip("/") + f"/browse/{data['key']}"
    status, data = http_json("POST", f"https://api.github.com/repos/{cfg['github_repo']}/issues", headers,
                             {"title": title, "body": body, "labels": labels})
    if status != 201:
        raise TicketError(f"GitHub refused the issue (HTTP {status}): {data.get('message', '')}")
    return f"#{data['number']}", data["html_url"]


def app_url() -> str:
    return os.environ.get("APP_URL", "")
