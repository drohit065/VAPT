"""Scan notifications to Slack, Microsoft Teams and email.

Webhook URLs must be https:// on a public host; requests are pinned to the validated address.
Delivery failures are logged and never affect the scan.
"""
from __future__ import annotations

import http.client
import json
import logging
import os
import smtplib
import socket
import ssl
from email.message import EmailMessage
from urllib.parse import urlsplit

from .security import ValidationError, assert_public_target, validate_target_url
from .summary import SEVERITIES

log = logging.getLogger("vapt.notify")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # Critical=0 ... Low=3
DEFAULTS = {"enabled": False, "on_completed": False, "on_failed": True, "on_new_findings": True,
            "min_severity": "High", "email_to": [], "smtp_host": "", "smtp_port": 587, "smtp_user": "",
            "smtp_from": "", "smtp_tls": "starttls"}


def validate_webhook(url: str) -> str:
    url = validate_target_url(url)
    if not url.startswith("https://"):
        raise ValidationError("Webhook URLs must use https://")
    assert_public_target(url)
    return url


def post_json(url: str, payload: dict, timeout: float = 15) -> int:
    """POST JSON to a public https URL, pinned to the address that was validated."""
    url = validate_webhook(url)
    p = urlsplit(url)
    ip = assert_public_target(url)[0]
    body = json.dumps(payload).encode()

    class Pinned(http.client.HTTPSConnection):
        def connect(self):
            sock = socket.create_connection((ip, self.port), self.timeout)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)

    conn = Pinned(p.hostname, p.port or 443, timeout=timeout, context=ssl.create_default_context())
    try:
        conn.request("POST", (p.path or "/") + (f"?{p.query}" if p.query else ""), body=body,
                     headers={"Content-Type": "application/json", "User-Agent": "VAPT-Scanner/1.0"})
        r = conn.getresponse()
        r.read(2000)
        if r.status >= 300:
            raise RuntimeError(f"webhook answered HTTP {r.status}")
        return r.status
    finally:
        conn.close()


def send_email(cfg: dict, password: str | None, subject: str, text: str) -> None:
    to = [a for a in cfg.get("email_to") or [] if a]
    if not to or not cfg.get("smtp_host"):
        return
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.get("smtp_from") or cfg.get("smtp_user") or "vapt-scanner@localhost"
    msg["To"] = ", ".join(to)
    msg.set_content(text)
    host, port = cfg["smtp_host"], int(cfg.get("smtp_port") or 587)
    ctx = ssl.create_default_context()
    if cfg.get("smtp_tls") == "ssl":
        server = smtplib.SMTP_SSL(host, port, timeout=20, context=ctx)
    else:
        server = smtplib.SMTP(host, port, timeout=20)
    try:
        if cfg.get("smtp_tls") == "starttls":
            server.starttls(context=ctx)
        if cfg.get("smtp_user") and password:
            server.login(cfg["smtp_user"], password)
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except smtplib.SMTPException:
            pass


def build_message(scan, project, new_counts: dict, app_url: str) -> tuple[str, str, bool]:
    """(subject, text, is_alert)."""
    counts = scan.counts or {}
    link = f"{app_url.rstrip('/')}/scans/{scan.id}/report" if app_url else f"scan #{scan.id}"
    if scan.status == "failed":
        subject = f"[VAPT] Scan failed: {project.name}"
        text = f"Scan #{scan.id} of {project.name} failed: {scan.error or 'unknown error'}\n{link}"
        return subject, text, True
    totals = ", ".join(f"{counts.get(s, 0)} {s}" for s in SEVERITIES)
    new_txt = ", ".join(f"{n} {s}" for s, n in new_counts.items() if n and s in SEVERITIES) or "none"
    subject = f"[VAPT] {project.name}: {sum(counts.get(s, 0) for s in SEVERITIES)} open finding(s)"
    if new_counts.get("Critical") or new_counts.get("High"):
        subject = f"[VAPT] New {'Critical' if new_counts.get('Critical') else 'High'} findings in {project.name}"
    text = (f"Scan #{scan.id} of {project.name} completed.\n"
            f"Open findings: {totals}\nNew since the previous scan: {new_txt}\n{link}")
    return subject, text, any(new_counts.values())


def should_notify(cfg: dict, scan, new_counts: dict) -> bool:
    if not cfg.get("enabled"):
        return False
    if scan.status == "failed":
        return bool(cfg.get("on_failed"))
    if cfg.get("on_completed"):
        return True
    if cfg.get("on_new_findings"):
        limit = SEV_RANK.get(cfg.get("min_severity") or "High", 1)
        return any(n and SEV_RANK.get(s, 99) <= limit for s, n in new_counts.items())
    return False


def new_counts_of(scan) -> dict:
    c = {s: 0 for s in SEVERITIES}
    for f in scan.findings:
        if f.is_new and f.status not in ("false_positive", "accepted_risk", "fixed"):
            c[f.severity] = c.get(f.severity, 0) + 1
    return c


def deliver(cfg: dict, secrets: dict, subject: str, text: str) -> list[str]:
    """Send to every configured channel; returns error strings (empty when all succeeded)."""
    errors = []
    if secrets.get("slack_url"):
        try:
            post_json(secrets["slack_url"], {"text": f"*{subject}*\n{text}"})
        except Exception as e:  # noqa: BLE001 - report and continue with other channels
            errors.append(f"Slack: {str(e)[:200]}")
    if secrets.get("teams_url"):
        try:
            post_json(secrets["teams_url"], {"text": f"**{subject}**\n\n{text}".replace("\n", "<br>")})
        except Exception as e:  # noqa: BLE001
            errors.append(f"Teams: {str(e)[:200]}")
    if cfg.get("email_to") and cfg.get("smtp_host"):
        try:
            send_email(cfg, secrets.get("smtp_password"), subject, text)
        except Exception as e:  # noqa: BLE001
            errors.append(f"Email: {str(e)[:200]}")
    return errors


def notify_scan(db, scan) -> None:
    from .settings_store import load

    try:
        stored, secrets = load(db, "notifications")
        cfg = {**DEFAULTS, **stored}
        new_counts = new_counts_of(scan) if scan.status == "completed" else {}
        if not should_notify(cfg, scan, new_counts):
            return
        subject, text, _ = build_message(scan, scan.project, new_counts, os.environ.get("APP_URL", ""))
        for err in deliver(cfg, secrets, subject, text):
            log.warning("scan %s notification failed: %s", scan.id, err)
    except Exception as e:  # noqa: BLE001 - notifications must never break a scan
        log.warning("scan %s notification error: %s", scan.id, str(e)[:300])
