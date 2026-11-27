#!/usr/bin/env bash
# Developer helper. Usage: ./scripts/dev.sh {up|down|reset-db|logs|test}
set -euo pipefail
cd "$(dirname "$0")/.."     # always run from the repo root

need_env() {
  if [ ! -f .env ]; then
    echo "ERROR: .env not found. Run:  cp .env.example .env   then edit it." >&2
    exit 1
  fi
  if grep -q "CHANGE_ME" .env; then
    echo "WARNING: .env still contains CHANGE_ME placeholders." >&2
  fi
}

# nginx mounts the server certificate and key; Compose fails if they are missing.
need_tls() {
  local cert key
  cert="$(grep -E '^TLS_CERT_PATH=' .env 2>/dev/null | cut -d= -f2- || true)"; cert="${cert:-./secrets/server.crt}"
  key="$(grep -E '^TLS_KEY_PATH=' .env 2>/dev/null | cut -d= -f2- || true)";   key="${key:-./secrets/server.key}"
  if [ ! -f "$cert" ] || [ ! -f "$key" ]; then
    echo "ERROR: TLS certificate or key not found ($cert, $key)." >&2
    echo "  Put the CA-issued pair there, or create a TEMPORARY self-signed one:" >&2
    echo "    ./scripts/dev_self_signed_cert.sh" >&2
    exit 1
  fi
}

case "${1:-help}" in
  up)        # build images and start everything in the background
    need_env
    need_tls
    # -V renews the frontend's node_modules volume, so new npm packages are
    # picked up after a rebuild (the database volume is not touched).
    docker compose up --build -d -V
    echo "App (HTTPS):  https://localhost"
    echo "API docs:     https://localhost/api/docs"
    echo "(Vite direct: http://localhost:5173 - no TLS, development only)"
    ;;
  down)      # stop and remove containers (data volume is kept)
    docker compose down
    ;;
  reset-db)  # DELETE the database volume and start fresh
    need_env
    need_tls
    read -r -p "This DELETES all local database data. Type 'yes' to continue: " answer
    if [ "$answer" != "yes" ]; then
      echo "Cancelled."
      exit 1
    fi
    docker compose down -v
    docker compose up --build -d -V
    ;;
  logs)      # follow logs; optionally name a service: ./scripts/dev.sh logs db
    docker compose logs -f --tail=100 "${@:2}"
    ;;
  test)      # run backend (pytest) and frontend (vitest) tests in throwaway containers
    need_env
    docker compose run --rm backend pytest
    docker compose run --rm frontend npm test
    ;;
  *)
    echo "Usage: ./scripts/dev.sh {up|down|reset-db|logs|test}"
    exit 1
    ;;
esac
