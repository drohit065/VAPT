"""Tests for container image references and Trivy image output parsing."""
import pytest

from app.normalize import parse_trivy_secrets
from app.security import ValidationError, parse_image_ref


@pytest.mark.parametrize("ref,registry,repo,tag", [
    ("nginx", "docker.io", "nginx", "latest"),
    ("nginx:1.27-alpine", "docker.io", "nginx", "1.27-alpine"),
    ("library/redis:7", "docker.io", "library/redis", "7"),
    ("ghcr.io/org/app:1.4.2", "ghcr.io", "org/app", "1.4.2"),
    ("123456789012.dkr.ecr.ap-south-1.amazonaws.com/team/app:prod", "123456789012.dkr.ecr.ap-south-1.amazonaws.com",
     "team/app", "prod"),
    ("registry.example.com:5000/app:v1", "registry.example.com:5000", "app", "v1"),
])
def test_valid_refs(ref, registry, repo, tag):
    info = parse_image_ref(ref)
    assert (info["registry"], info["repo"], info["tag"]) == (registry, repo, tag)


def test_digest_ref():
    d = "sha256:" + "a" * 64
    info = parse_image_ref(f"nginx@{d}")
    assert info["digest"] == d and info["tag"] == ""


@pytest.mark.parametrize("ref", ["", "-flag", "UPPER/case", "nginx:", "localhost:5000/app", "10.0.0.5:5000/app",
                                 "127.0.0.1/app", "nginx;rm -rf /", "a" * 600, "nginx:tag with space"])
def test_invalid_refs(ref):
    with pytest.raises(ValidationError):
        parse_image_ref(ref)


def test_parse_trivy_secrets():
    data = {"Results": [{"Target": "/app/.env", "Class": "secret", "Secrets": [{
        "RuleID": "aws-access-key-id", "Category": "AWS", "Severity": "CRITICAL", "Title": "AWS Access Key ID",
        "StartLine": 3, "Match": "AWS_ACCESS_KEY_ID=********************"}]}]}
    f = parse_trivy_secrets(data)
    assert len(f) == 1
    assert f[0]["severity"] == "Critical" and f[0]["check"] == "secrets" and f[0]["file_path"] == "app/.env"
    assert f[0]["line"] == 3 and f[0]["cwe"].startswith("CWE-798")
