"""Tests for notification rules, messages and the settings API."""
from types import SimpleNamespace

import pytest

from app.notifier import DEFAULTS, build_message, should_notify
from app.settings_store import merge_secrets


def scan(status="completed", counts=None, error=None):
    return SimpleNamespace(id=7, status=status, error=error,
                           counts=counts or {"Critical": 1, "High": 2, "Medium": 0, "Low": 0})


NEW_HIGH = {"Critical": 0, "High": 1, "Medium": 0, "Low": 0}
NEW_LOW = {"Critical": 0, "High": 0, "Medium": 0, "Low": 3}
NONE = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}


def test_rules():
    cfg = {**DEFAULTS, "enabled": True}
    assert should_notify(cfg, scan(), NEW_HIGH)
    assert not should_notify(cfg, scan(), NEW_LOW)          # below min severity (High)
    assert not should_notify(cfg, scan(), NONE)
    assert should_notify(cfg, scan("failed"), {})
    assert should_notify({**cfg, "min_severity": "Low"}, scan(), NEW_LOW)
    assert should_notify({**cfg, "on_completed": True}, scan(), NONE)
    assert not should_notify({**cfg, "enabled": False}, scan(), NEW_HIGH)
    assert not should_notify({**cfg, "on_failed": False}, scan("failed"), {})


def test_messages():
    p = SimpleNamespace(name="shop-api")
    subj, text, alert = build_message(scan(), p, NEW_HIGH, "https://vapt.example.com/")
    assert "New High findings in shop-api" in subj and alert
    assert "https://vapt.example.com/scans/7/report" in text and "1 High" in text
    subj, text, _ = build_message(scan("failed", error="clone failed"), p, {}, "")
    assert "failed" in subj and "clone failed" in text


def test_merge_secrets_write_only():
    cur = {"slack_url": "https://hooks.slack.com/a", "smtp_password": "pw"}
    assert merge_secrets(cur, {"slack_url": "", "teams_url": "https://t"}, []) == {
        "slack_url": "https://hooks.slack.com/a", "smtp_password": "pw", "teams_url": "https://t"}
    assert merge_secrets(cur, {}, ["smtp_password"]) == {"slack_url": "https://hooks.slack.com/a"}


@pytest.mark.parametrize("url", ["http://hooks.slack.com/x", "https://127.0.0.1/x", "https://localhost/x"])
def test_webhook_validation_rejects(url):
    from app.notifier import validate_webhook
    from app.security import ValidationError
    with pytest.raises(ValidationError):
        validate_webhook(url)
