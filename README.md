# VAPT Scanner

A self-hosted security scanner with a web dashboard: static analysis of source code (SAST) and
scanning of live websites and APIs (DAST).

It **only reads and reports**. It never builds, executes, modifies or auto-fixes the code it
scans. Code is cloned or unzipped into a temporary folder per scan, read by static analysers,
and the folder is deleted when the scan ends. Live targets only receive ordinary HTTP requests.

**Source code** (Git repository or zip upload):

| Check (switchable per scan) | Tool |
|---|---|
| Code flaws | Semgrep (`--config auto`) |
| Vulnerable dependencies | Trivy `fs` |
| Hardcoded secrets, including Git history | Gitleaks |
| Docker and Terraform files | Trivy `config` |
| AI review (off by default) | Claude API: filters false positives, finds logic flaws (Phase 4) |

**Website / API** (up to 5 live URLs per scan, e.g. a frontend and its backend API):

| Check (switchable per scan) | Tool |
|---|---|
| Web security checks: security headers, cookie flags, TLS certificate and protocol, HTTP→HTTPS redirect, CORS, TRACE, exposed files (`/.git`, `/.env`, Spring Actuator, server-status, phpinfo, directory listing, Swagger/OpenAPI) | Built in |
| Known CVEs and misconfigurations | Nuclei (community templates, refreshed daily) |

### Live URL scanning: rules

* **Only scan targets you own or have written permission to test.** The New scan form requires
  you to confirm this, and the confirmation is recorded on the scan.
* Private, loopback and link-local addresses (including cloud metadata `169.254.169.254`) are
  refused. Every built-in request is pinned to an address checked as public, and redirects are
  never followed, so a target cannot bounce the scanner into your internal network.
* Nuclei runs HTTP and SSL templates only, at 30 requests/second, with `dos`, `fuzz`,
  `intrusive` and brute-force templates excluded and interactsh (out-of-band callbacks to
  third-party servers) disabled. Expect a few thousand requests and a few minutes per target.
  Prefer a staging environment, and tell whoever monitors the target's WAF / logs.
* On EC2, require IMDSv2 with a hop limit of 1 (EC2 console → instance → Actions → Instance
  settings → Modify instance metadata options) so no container can reach instance credentials.

## Architecture

```
browser ──► frontend (nginx, React)  :HTTP_PORT ─┐
                 │ /api                           │ only this port is published
                 ▼                                │
            backend (FastAPI) ──► db (PostgreSQL) ◄── worker (Semgrep, Trivy, Gitleaks, Nuclei)
                 │                                     ▲
                 └──── uploads volume (zip files) ─────┘
```

* `backend`, `worker` and `db` are not reachable from outside the Docker network.
* The worker polls the database for queued scans and runs them one at a time.

## Deploy on a fresh Ubuntu EC2 instance

Tested target: Ubuntu 22.04 / 24.04, `t3.medium` or larger (2 vCPU, 4 GB RAM), 30 GB disk.
Both x86_64 and ARM (Graviton) instances work.

### 1. Security group

Open **one inbound port: TCP 80** (or whatever you set `HTTP_PORT` to), plus TCP 22 for SSH.

> **Restrict both rules to trusted IPs only** (your office or VPN range, e.g. `203.0.113.10/32`),
> never `0.0.0.0/0`. The dashboard holds vulnerability reports for your code. It serves plain
> HTTP; if it must be reached over the internet, put it behind an HTTPS load balancer or
> reverse proxy.

Outbound HTTPS (443) must be allowed: the worker downloads Semgrep rules (`semgrep.dev`),
the Trivy vulnerability database (`mirror.gcr.io` / `ghcr.io`), Nuclei templates (`github.com`), clones Git repositories and reaches the live targets you scan (HTTP/HTTPS).

### 2. Install Docker

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
```

### 3. Clone

```bash
git clone https://github.com/drohit065/vapt.git
cd vapt
```

### 4. Configure `.env`

```bash
cp .env.example .env
chmod 600 .env
```

Generate the secrets and paste them into `.env`:

```bash
openssl rand -hex 32          # JWT_SECRET
openssl rand -hex 24          # POSTGRES_PASSWORD
python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"   # TOKEN_ENCRYPTION_KEY
```

Then edit the file:

```bash
nano .env
```

Set at least `ADMIN_USERNAME`, `ADMIN_PASSWORD` (12+ characters), `JWT_SECRET`,
`TOKEN_ENCRYPTION_KEY` and `POSTGRES_PASSWORD`. To enable the AI review, also set
`ANTHROPIC_API_KEY` (and optionally `ANTHROPIC_MODEL`). The backend refuses to start while
placeholder values are still in place.

### 5. Start

```bash
docker compose up -d --build
```

The first build takes a few minutes (it installs the scanners). Then open
`http://<EC2-public-IP>/` and sign in with the admin credentials from `.env`.

Useful commands:

```bash
docker compose ps
docker compose logs -f worker
docker compose pull && docker compose up -d --build   # after git pull
```

## Test with the sample project

`samples/vulnerable-app` is a small, deliberately vulnerable Flask + JS app (fake secrets only).

* **Zip:** on your laptop run `cd samples && zip -r vulnerable-app.zip vulnerable-app`, then
  upload the zip on **New scan → Zip upload**.
* **Git:** scan `https://github.com/drohit065/vapt` itself; the sample is inside it.

Expect Critical/High findings in every check: SQL and command injection, `eval`, pickle,
old Flask/lodash CVEs, the planted secrets, a root Docker image and a public S3 bucket.

## Security of the tool itself

* Scanned code is never executed or built; only static analysers read it.
* One temporary folder per scan, deleted when the scan ends (also after failures and worker restarts).
* Zip extraction rejects absolute paths and `..` (zip slip), skips symlinks and `.git`
  folders, never sets execute bits, and enforces upload size, expanded size and file count limits.
* Git URLs must be `https://` with a host name that resolves to a public address (blocks
  internal networks and cloud metadata). Credentials in URLs are refused. Redirects, non-https
  protocols, hooks and submodules are disabled during clone.
* Every subprocess is started with an argument list; user input never reaches a shell.
* Git tokens are Fernet-encrypted while queued, passed to git through `GIT_ASKPASS` (never on
  the command line or in the URL), wiped from the database right after the clone, scrubbed
  from error messages, and never returned by the API.
* Secret values found by Gitleaks, and secret-looking assignments, are masked in all stored snippets.
* Scanners run as an unprivileged user with a minimal environment (no DB password or API keys).
* All secrets come from `.env`, which is git-ignored. Only `.env.example` is committed.
* Every API route except `POST /api/auth/login` requires a JWT. Failed logins are rate limited.
  API docs routes are disabled.

## Development

Backend tests:

```bash
cd backend
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

Frontend dev server (proxies `/api` to `localhost:8000`):

```bash
cd frontend && npm install && npm run dev
```
