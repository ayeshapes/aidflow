# AidFlow

Web app for managing aid donations, procurement, inventory, beneficiaries and
distributions, with strong security controls. Course project for CS-353
Information Security, NUST SEECS.

**Stack:** FastAPI + SQLAlchemy + Alembic + PostgreSQL 16, React + Vite + Tailwind,
Docker Compose, nginx (HTTPS/mTLS), pytest.
**Roles:** admin, warehouse, field, auditor.

## Repository layout
| Folder | Purpose |
|---|---|
| `backend/` | FastAPI application, migrations, tests |
| `frontend/` | React + Vite app |
| `nginx/` | Reverse proxy config (HTTPS/mTLS) |
| `scripts/` | Helper scripts (dev commands, key check, backups) |
| `documentation/` | Reports, Access Control Policy |
| `secrets/` | Local keys and certificates (git-ignored, see its README) |

## Branch model
- `develop`: the working branch. Feature branches merge here by pull request.
- `main`: protected. Updated only at integration checkpoints, by a pull request
  from `develop` with 1 approval. Nobody pushes to it directly.
- `feature/<ticket-id>-short-name`: one branch per ticket, always created from
  `develop`, e.g. `feature/F-02-docker-compose`.

Flow: `feature/...` -> PR -> `develop` -> (checkpoint) PR -> `main`.

## Setup

### Prerequisites
- **Docker Desktop** (includes Docker Compose v2). Check: `docker compose version`.
- **Windows only:** WSL2 with Docker Desktop's WSL integration turned on. Clone
  and work **inside the WSL filesystem** (e.g. `~/aidflow`), not under `/mnt/c`:
  it is much faster and file-change detection works.
- **OpenSSL** (to generate secrets; already present on Linux, macOS and WSL).
- Git.

### First-time setup
```bash
# 1. Install the private-key pre-commit hook (once per clone)
chmod +x scripts/*.sh && ln -sf ../../scripts/check_no_private_keys.sh .git/hooks/pre-commit

# 2. Create your local .env (git-ignored) and replace every CHANGE_ME
cp .env.example .env
openssl rand -hex 32     # run once per secret: JWT_SECRET, BACKUP_KEY, POSTGRES_PASSWORD
openssl rand -base64 32  # FIELD_ENCRYPTION_KEY (Saleha confirms the exact format)
# Pick a POSTGRES_USER and POSTGRES_DB, then make DATABASE_URL match:
#   postgresql+psycopg2://<user>:<password>@db:5432/<dbname>
# The host must stay "db". Never use a shared or remote database.

# 3. Build and start everything
docker compose up --build
```
Shortcut: `./scripts/dev.sh up` does step 3 in the background.

### HTTPS (nginx, ticket A-05)
nginx is the only way in to the backend. It listens on **443** (port 80 redirects to 443) and
needs a server certificate and key at the paths in `.env` (`TLS_CERT_PATH`, `TLS_KEY_PATH`;
default `./secrets/server.crt` and `./secrets/server.key`), mounted read-only.
```bash
# CA-issued pair not ready yet? Create a TEMPORARY self-signed one (dev only, 30 days):
./scripts/dev_self_signed_cert.sh
./scripts/dev.sh up
```
Replace the temporary files with the CA-issued pair as soon as you have it. Config lives in
`nginx/` (`aidflow.conf` + `snippets/`); how to prove the TLS setup (SEC-10):
`documentation/sec10_tls_evidence.md`.

### URLs
| What | URL | What you should see |
|---|---|---|
| App through nginx (HTTPS) | https://localhost | the **Sign in** page; after login, "Welcome, <you>" and a green **Backend is healthy** box |
| Health through nginx | https://localhost/api/health | `{"status":"ok","db":true}` |
| API docs through nginx | https://localhost/api/docs | Swagger UI |
| `http://localhost` | | redirects (301) to `https://localhost` |
| Frontend, Vite direct (dev only, no TLS) | http://localhost:5173 | the same app, bypassing nginx |

The backend publishes **no** host port (`localhost:8000` is closed); it is reachable only
through nginx. With a temporary certificate the browser shows a warning; with `curl` use
`--cacert secrets/server.crt`. HSTS makes browsers insist on HTTPS for `localhost` after the
first visit, so `http://localhost:5173` may stop working in that browser (see
`nginx/snippets/security_headers.conf` for how to undo it); use `https://localhost`.

PostgreSQL is **not** published to your machine. Only containers in this project
can reach it, and each developer has their own private copy of the data.

### Daily commands
| Command | What it does |
|---|---|
| `./scripts/dev.sh up` | build and start all services in the background |
| `./scripts/dev.sh down` | stop and remove containers (data is kept) |
| `./scripts/dev.sh reset-db` | **delete** the local database and start fresh (asks first) |
| `./scripts/dev.sh logs [service]` | follow logs, e.g. `logs db` |
| `./scripts/dev.sh test` | run the backend tests in a container |

If a script says "permission denied", run `chmod +x scripts/*.sh` once.

### Troubleshooting

**"port is already allocated" / "address already in use" (80, 443 or 5173)**
Another program, or an old copy of this stack, is using the port.
1. Stop old copies: `docker compose down`.
2. Find the program using the port:
   - Linux/macOS/WSL: `lsof -i :443`
   - Windows PowerShell: `netstat -ano | findstr :443`
3. Stop that program (on Windows, IIS or another web server often holds 80/443), or change
   the left number in `docker-compose.yml` (e.g. `"8443:443"`) and browse to `https://localhost:8443`
   (the port-80 redirect then points at 443, so use the HTTPS URL directly).

**`bind source path does not exist` mentioning `server.crt` / `server.key`**
The certificate pair is missing. Put the CA-issued files at the `TLS_CERT_PATH` / `TLS_KEY_PATH`
paths from `.env`, or run `./scripts/dev_self_signed_cert.sh` for a TEMPORARY one.

**"database not ready" / backend cannot connect / "connection refused"**
The backend waits for the database healthcheck, so this usually means the
database itself is unhealthy.
1. `docker compose ps`: the `db` service should say `healthy`.
2. `./scripts/dev.sh logs db` and read the last lines.
3. `password authentication failed`: Postgres only reads `POSTGRES_PASSWORD` the
   **first** time the volume is created. If you changed it in `.env` later, run
   `./scripts/dev.sh reset-db`.
4. Check that `DATABASE_URL` has host `db` and the same user, password and
   database name as the `POSTGRES_*` values.
5. Compose says `set POSTGRES_PASSWORD in .env`: you have no `.env` file. Run
   `cp .env.example .env`.

**Frontend shows "Cannot reach the server" or a red error box**
1. `docker compose ps`: is `backend` running? Open https://localhost/api/health (through nginx;
   the backend has no host port). A `502` there means nginx cannot reach the backend:
   `./scripts/dev.sh logs backend nginx`.
2. If that works but the page does not, the Vite proxy cannot reach the backend:
   `./scripts/dev.sh logs frontend`.
3. After editing `package.json` always use `./scripts/dev.sh up` (it renews the
   `node_modules` volume). Plain `docker compose up --build` can keep an old one
   and you get "Cannot find module" errors.

**`bad interpreter` / `\r` errors when running a script (Windows)**
The script got Windows line endings. `.gitattributes` prevents this for new
clones; to repair a file, run `sed -i 's/\r$//' scripts/*.sh`.

## Tests
```bash
bash scripts/test_check_no_private_keys.sh   # key scanner
bash scripts/test_f02_config.sh              # compose and .env.example rules
bash scripts/test_a05_config.sh              # nginx / HTTPS rules (A-05)
./scripts/dev.sh test                        # backend pytest + frontend vitest (in Docker)
# Evidence for the security tests (SEC-01/02/03/11): documentation/testing_report.md
# SEC-01 (app/tests/test_security.py) reads every route from app.routes. A new route that
# forgets its auth dependency fails it; a deliberately public one goes in PUBLIC_ROUTES there.
```

## Backend layout (`backend/app`)
| Folder | Purpose |
|---|---|
| `main.py` | creates the app, CORS, error handlers, mounts `/api` |
| `api/` | routers (one file per area); all mounted under `/api` |
| `core/` | `config.py` (settings), `errors.py` (error format), `security.py`, `permissions.py` |
| `db/` | `session.py` (engine, `get_db`), `base.py` (model parent class) |
| `models/` `schemas/` `services/` | database models, request/response shapes, business logic |
| `tests/` | pytest tests |

Every error, including validation (422) and crashes (500), is returned as
`{"error": {"code": "...", "message": "..."}}`. List endpoints use
`PageParams` + `paginate()` and return `{items, total, page, page_size}`.

### Authentication (ticket A-01)
```bash
docker compose run --rm backend alembic upgrade head              # create tables
docker compose run --rm backend python -m app.create_admin <name> # first admin (hidden password prompt)
```
Then `POST /api/auth/login` returns a Bearer token. Passwords need 12+ characters (max 72 bytes).
User management is under `/api/users` (admin only); there is no delete, only deactivate.

### Login protection (ticket A-04)
`POST /api/auth/login` has two independent defences against password guessing:

| Defence | Rule | Where it lives | Response |
|---|---|---|---|
| Rate limit | 5 attempts per minute per **client IP + username** (sliding window; usernames are trimmed and lower-cased) | `core/rate_limit.py`, in process memory | `429`, code `RATE_LIMITED`, `Retry-After: <seconds>` |
| Account lockout | 5 **consecutive** failures lock the account for 15 minutes; a successful login resets the count | `users.failed_login_count`, `users.locked_until`; `services/auth.py` | the same `401` as any failed login |

- A locked account refuses even the correct password, and answers exactly like an unknown
  user (same body, same bcrypt cost), so lockouts cannot be used to discover usernames.
  Attempts made while locked are not counted and do not extend the lock. When the lock
  runs out the count restarts from 0.
- The lockout is written to the audit log as `account_locked` (once, on the 5th failure).
- The rate limiter keeps its counters per process. Before running more than one uvicorn
  worker, move them to Redis or the database. The lockout is in the database and is not affected.
- Behind nginx, uvicorn runs with `--proxy-headers --forwarded-allow-ips=*` (set in `docker-compose.yml`)
  so the client IP is the real one. `*` is safe only because nginx is the sole way to reach the
  backend (no host port) and it overwrites `X-Forwarded-For` with the real peer address. Do not
  read `X-Forwarded-For` in application code: any client can forge it.
- There is no admin "unlock" yet; a lock simply expires after 15 minutes.

Apply the new columns with `docker compose run --rm backend alembic upgrade head`.

Never commit `.env` or anything in `secrets/`. Only `.env.example` is committed.

## Frontend layout (`frontend/src`) (ticket A-03)
| Path | Purpose |
|---|---|
| `api/client.js` | the only code that calls the backend; adds the Bearer token, turns errors into `ApiError`, reports 401s |
| `auth/AuthContext.jsx` | `login()`, `logout()`, current user; token kept in memory + `sessionStorage` (trade-offs explained in the file) |
| `auth/permissions.js` | copy of the backend capability table, for UI decisions only; **keep in sync with `backend/app/core/permissions.py`** |
| `auth/ProtectedRoute.jsx` | redirects to `/login` when logged out; shows the 403 page when the role lacks `capability` |
| `pages/` `components/` | Login, Users, Home, 403, 404, and the logged-in page frame |

Protect a route in `App.jsx` with `<Route element={<ProtectedRoute capability="manage_users" />}>`.
The frontend check only decides what to show; the API enforces every rule again.
