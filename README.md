# VAPT Scanner

A self-hosted security scanner with a web dashboard: static analysis of source code (SAST),
scanning of live websites and APIs (DAST), infrastructure checks and container image scanning.

**Container image** (Docker Hub, GHCR, ECR or any public registry; optional registry login):
OS and library vulnerabilities, secrets in image layers, image misconfigurations (root user, no
HEALTHCHECK) and end-of-life base images, with Trivy `image --image-src remote` (pulled straight
from the registry, never run, no Docker daemon needed).

**Team features:** users with roles (viewer: read-only; analyst: start scans, triage, schedules;
admin: manage users, audit log) next to the built-in admin from `.env`; an audit log of logins,
scans, triage decisions, exports and user changes; scheduled daily / weekly re-scans of Git,
website and image projects (credentials are never stored, so scheduled runs are unauthenticated).

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
| Crawl + passive scan, Swagger/OpenAPI import (spec found automatically next to `swagger-ui`) | OWASP ZAP |
| Active scan: SQL injection, XSS, path traversal, command injection… (**off by default**) | OWASP ZAP |
| Access control: each protected endpoint as user A, without credentials and as user B (GET only) | Built in |

Optional **authenticated scanning**: paste the request headers of a logged-in test session
(e.g. `Authorization: Bearer …` or `Cookie: …`) for user A, and optionally user B. They are
encrypted while queued, wiped from the database when the worker picks the scan up, used only in
memory, scrubbed from errors and findings, and passed to Nuclei via a `0600` file and to ZAP via
replacer rules that are removed after the scan.

**Every report** supports triage (Open / False positive / Accepted risk / Fixed, carried over to
later scans), comparison with the previous scan (new / fixed / still present), CVSS v3 scores,
and CSV, SARIF 2.1.0 and PDF export.

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
* The ZAP **active scan** sends real attack payloads and may create records, send emails or
  trip a WAF. Use it on staging, with test accounts. ZAP runs in its own container on a network
  shared only with the worker (it cannot reach the database), limited to the target hosts.
  ZAP needs about 1–1.5 GB RAM: use `t3.large` (8 GB) or bigger when you scan live URLs.
* On EC2, require IMDSv2 with a hop limit of 1 (EC2 console → instance → Actions → Instance
  settings → Modify instance metadata options) so no container can reach instance credentials.

## Architecture

```
browser ──► frontend (nginx, React)  :HTTP_PORT ─┐
                 │ /api                           │ only this port is published
                 ▼                                │
            backend (FastAPI) ──► db (PostgreSQL) ◄── worker (Semgrep, Trivy, Gitleaks, Nuclei) ──► zap (OWASP ZAP, scan network only)
                 │                                     ▲
                 └──── uploads volume (zip files) ─────┘
```

* `backend`, `worker` and `db` are not reachable from outside the Docker network.
* The worker polls the database for queued scans and runs them one at a time.

## Deploy on a fresh Ubuntu EC2 instance

Tested target: Ubuntu 22.04 / 24.04. Use **`t3.large` (2 vCPU, 8 GB RAM) or larger** with a
**40 GB** disk: OWASP ZAP alone needs 1–1.5 GB RAM and the scanner databases / images take space.
(`t3.medium` is enough if you only scan code, not live URLs.) x86_64 and ARM (Graviton) both work.

**Instance metadata:** EC2 console → instance → *Actions → Instance settings → Modify instance
metadata options* → IMDSv2 **Required**, hop limit **1**. Containers then cannot read the
instance's IAM credentials even if a scanner were tricked into requesting them.

### 1. Security group

| Setup | Inbound rules |
|---|---|
| **A. HTTPS with Caddy** (recommended, built in) | TCP 443 and TCP 80 (Let's Encrypt needs 80/443 reachable for the certificate) + TCP 22 from your IP |
| **B. HTTPS on an AWS load balancer** | ALB with an ACM certificate (443) → instance TCP 80 from the ALB's security group only; TCP 22 from your IP |
| **C. Plain HTTP** (testing only) | TCP 80 (or `HTTP_PORT`) + TCP 22, both from trusted IPs only |

> Restrict SSH (and in setup C, the web port) to trusted IPs such as your office / VPN range
> (e.g. `203.0.113.10/32`), never `0.0.0.0/0`. The dashboard holds vulnerability reports. With
> setup B you can also restrict the ALB to trusted IPs; with setup A, Let's Encrypt must reach port 80/443.

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
openssl rand -hex 24          # ZAP_API_KEY
python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"   # TOKEN_ENCRYPTION_KEY
```

Then edit the file:

```bash
nano .env
```

Set at least `ADMIN_USERNAME`, a **strong** `ADMIN_PASSWORD` (16+ random characters, e.g.
`openssl rand -base64 18`), `JWT_SECRET`, `TOKEN_ENCRYPTION_KEY`, `POSTGRES_PASSWORD` and
`ZAP_API_KEY`. Also set:

| Variable | When |
|---|---|
| `APP_URL` | always: the public dashboard address, used for links in notifications and tickets (e.g. `https://vapt.example.com`) |
| `DOMAIN`, `ACME_EMAIL` | setup A (Caddy) |
| `TRUSTED_PROXY_CIDR` | setup B: the VPC CIDR of the ALB (e.g. `10.0.0.0/16`) so login rate limiting and the audit log see real client IPs |
| `HTTP_PORT` | setups B / C if not 80 |
| `ANTHROPIC_API_KEY` | only for the (optional) AI review |

The backend refuses to start while placeholder values are still in place. Keep `TOKEN_ENCRYPTION_KEY`
safe and unchanged: it decrypts stored webhook URLs, ticketing tokens and saved schedule credentials.

### 5. Start

```bash
# Setup A: HTTPS with automatic Let's Encrypt certificates
docker compose -f docker-compose.yml -f docker-compose.https.yml up -d --build

# Setups B and C: plain HTTP on HTTP_PORT (behind the ALB for B)
docker compose up -d --build
```

The first build takes several minutes (it installs the scanners). Then open `https://<DOMAIN>/`
(or `http://<EC2-IP>/` for C) and sign in with the admin credentials from `.env`. Create named
users with their own roles under **Users** instead of sharing the built-in admin.

Useful commands (add `-f docker-compose.yml -f docker-compose.https.yml` for setup A):

```bash
docker compose ps
docker compose logs -f worker
git pull && docker compose up -d --build      # update
```

### Shared host with an existing nginx (setup D)

When the server already runs nginx on 80/443 with your certificate (e.g. a `*.prismxai.com` wildcard),
don't use Caddy; publish the UI on localhost only and add a server block:

```bash
# .env
HTTP_BIND=127.0.0.1
HTTP_PORT=18096                      # any free port: check with  sudo ss -ltnp | grep 18096
TRUSTED_PROXY_CIDR=172.16.0.0/12     # nginx reaches the container through the Docker bridge
APP_URL=https://vapt-tool.example.com

# Pre-flight on older hosts / hypervisors: the base image must not crash (exit code 139 = segfault)
docker run --rm python:3.12-slim python -c "import ssl, hashlib, json; print('base image OK')"
# If it segfaults (exit 139), test the other base:  docker run --rm python:3.12-slim-bookworm python -c "print(1)"
# and set PYTHON_IMAGE=python:3.12-slim-bookworm in .env if that one works.
# Debian 11 "bullseye" images are past end of life: their package mirrors are being retired.

sudo cp deploy/nginx-vapt-tool.conf /etc/nginx/conf.d/vapt-tool.conf   # edit server_name + cert paths
sudo nginx -t && sudo systemctl reload nginx

# old runc (error "flag provided but not defined: -keep"): use the classic builder
DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 docker compose up -d --build
```

#### Hosts with an old container runtime (runc < 1.0.3, libseccomp < 2.5)

Symptoms: builds fail with `flag provided but not defined: -keep`, `apt-get` fails with
`Problem executing scripts APT::Update::Post-Invoke`, Python fails with `can't start new thread`.
Check with `runc --version` and `rpm -q libseccomp`. Current glibc uses the `clone3` syscall,
which those versions' seccomp filter rejects. Without touching the host's runtime:

```bash
# 1. Base image with the OS packages, prepared once with seccomp relaxed for this one container
docker run --name vapt-osbase --security-opt seccomp=unconfined python:3.12-slim sh -c \
  "apt-get update && apt-get install -y --no-install-recommends git ca-certificates nmap && rm -rf /var/lib/apt/lists/*"
docker commit vapt-osbase vapt-pybase:latest && docker rm vapt-osbase

# 2. .env
PYTHON_IMAGE=vapt-pybase:latest
COMPOSE_FILE=docker-compose.yml:deploy/docker-compose.old-runc.yml   # seccomp relaxed for backend, worker, zap only

# 3. Build with the classic builder, then start
for s in backend worker frontend; do
  f=Dockerfile; ctx=./backend; [ $s = worker ] && f=Dockerfile.worker; [ $s = frontend ] && ctx=./frontend
  DOCKER_BUILDKIT=0 docker build -t vapt-$s --build-arg PYTHON_IMAGE=vapt-pybase:latest -f $ctx/$f $ctx || break
done && docker compose up -d --no-build
```

The override drops all Linux capabilities and sets `no-new-privileges` for those containers to make
up for the relaxed filter. Remove it (and rebuild normally) once the host runs runc >= 1.0.3 and
libseccomp >= 2.5.

On a shared box, do **not** change the instance metadata hop limit without checking the other
workloads; instead block instance metadata for the VAPT networks only (after the first start):

```bash
for n in vapt_default vapt_scan; do
  s=$(docker network inspect "$n" --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}')
  sudo iptables -I DOCKER-USER -s "$s" -d 169.254.169.254 -j DROP
done
```
(Not persistent across reboots / Docker restarts unless you save the rules, e.g. with `iptables-services`.)

### 6. Backups

The `backup` service writes `backups/vapt-YYYY-MM-DD.sql.gz` every night at 02:30 UTC and keeps
`BACKUP_KEEP_DAYS` (default 14) days. Copy the folder off the instance (e.g. `aws s3 sync backups/
s3://your-bucket/vapt/`) or use EBS snapshots. Restore:

```bash
gunzip -c backups/vapt-2026-11-14.sql.gz | docker compose exec -T db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"
```

Back up `.env` separately (a password manager or AWS Secrets Manager): without the same
`TOKEN_ENCRYPTION_KEY` the encrypted settings in a restored database cannot be read.

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

## CI/CD integration

1. **Settings → API keys & CI/CD**: create a key with the *analyst* role (shown once; only its hash is stored).
2. Add repository secrets `VAPT_URL` (this dashboard, reachable from the CI runner over HTTPS) and `VAPT_API_KEY`.
3. Copy [`ci/github-actions-example.yml`](ci/github-actions-example.yml) to `.github/workflows/vapt.yml`.

[`ci/vapt-scan.sh`](ci/vapt-scan.sh) (needs `curl` and `jq`) zips the checked-out code with `git archive` (or scans a
Git URL, live URL or container image), waits for the scan and calls the quality gate
`GET /api/scans/{id}/gate?fail_on=High&new_only=false`: exit code `0` passed, `1` blocking findings, `2` error.
With `VAPT_SARIF=vapt.sarif` it also downloads SARIF for GitHub code scanning. Pull requests can use
`VAPT_NEW_ONLY=true` so only findings introduced since the previous scan block the merge. Findings triaged as
false positive or accepted risk never block.
