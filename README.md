# VAPT Scanner

A self-hosted source-code security scanner with a web dashboard. It **only reads and reports**:
it never builds, executes, modifies or auto-fixes the code it scans.

> Status: Phase 1 (Docker Compose skeleton, login, projects list). Scanning, reports, PDF
> and AI review arrive in later phases.

## Stack

| Service    | What it is                                  |
|------------|---------------------------------------------|
| `frontend` | React (Vite) build served by nginx, port 8080 inside the container, published on `HTTP_PORT` |
| `backend`  | Python FastAPI, internal only (reached via nginx at `/api`) |
| `db`       | PostgreSQL 16, internal only                |

## Local run

```bash
cp .env.example .env      # then edit every value
docker compose up -d --build
```

Open `http://localhost/` and sign in with `ADMIN_USERNAME` / `ADMIN_PASSWORD` from `.env`.
