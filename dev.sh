#!/usr/bin/env bash

# APTHunter local development launcher.
# Starts FastAPI, Celery worker, and Vite frontend in one terminal.

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
BACKEND_VENV_DIR="$BACKEND_DIR/venv"

BACKEND_PORT="${BACKEND_PORT:-8001}"
FRONTEND_PORT="${FRONTEND_PORT:-6678}"
START_REDIS="${START_REDIS:-1}"

if [[ -x "$BACKEND_VENV_DIR/bin/uvicorn" && -x "$BACKEND_VENV_DIR/bin/celery" ]]; then
    DEFAULT_UVICORN_CMD="$BACKEND_VENV_DIR/bin/uvicorn app.main:app --host 0.0.0.0 --port ${BACKEND_PORT}"
    DEFAULT_CELERY_CMD="$BACKEND_VENV_DIR/bin/celery -A celery_worker worker --loglevel=info"
else
    DEFAULT_UVICORN_CMD="uvicorn app.main:app --host 0.0.0.0 --port ${BACKEND_PORT}"
    DEFAULT_CELERY_CMD="celery -A celery_worker worker --loglevel=info"
fi

UVICORN_CMD="${UVICORN_CMD:-$DEFAULT_UVICORN_CMD}"
CELERY_CMD="${CELERY_CMD:-$DEFAULT_CELERY_CMD}"
FRONTEND_CMD="${FRONTEND_CMD:-pnpm dev}"

PIDS=()

log() {
    printf '[dev] %s\n' "$*"
}

die() {
    printf '[dev] ERROR: %s\n' "$*" >&2
    exit 1
}

load_env_file() {
    local env_file="$1"
    local line key value

    [[ -f "$env_file" ]] || return 0

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"

        [[ -z "$line" || "$line" == \#* ]] && continue

        if [[ "$line" == export[[:space:]]* ]]; then
            line="${line#export }"
            line="${line#"${line%%[![:space:]]*}"}"
        fi

        [[ "$line" == *=* ]] || continue

        key="${line%%=*}"
        value="${line#*=}"
        key="${key%"${key##*[![:space:]]}"}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"

        [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue

        if [[ "$value" == \"*\" && "$value" == *\" ]]; then
            value="${value:1:${#value}-2}"
        elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
            value="${value:1:${#value}-2}"
        fi

        export "$key=$value"
    done < "$env_file"

    log "loaded env: ${env_file#$ROOT_DIR/}"
}

set_local_defaults() {
    export MINIO_ENDPOINT="${MINIO_ENDPOINT:-127.0.0.1:9000}"
    export MINIO_ACCESS_KEY="${MINIO_ACCESS_KEY:-minioadmin}"
    export MINIO_SECRET_KEY="${MINIO_SECRET_KEY:-123456789}"
    export MINIO_BUCKET="${MINIO_BUCKET:-uploads}"

    # docker-compose exposes MySQL on 127.0.0.1:3307 for host-side development.
    export MYSQL_URL="${MYSQL_URL:-mysql+pymysql://apthunter:4CyUhr2zu6!@127.0.0.1:3307/apthunter_new}"

    export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
    export CELERY_BROKER_URL="${CELERY_BROKER_URL:-$REDIS_URL}"
    export CELERY_RESULT_BACKEND="${CELERY_RESULT_BACKEND:-$REDIS_URL}"

    export VITE_API_PROXY_TARGET="${VITE_API_PROXY_TARGET:-http://127.0.0.1:${BACKEND_PORT}}"
}

check_requirements() {
    [[ -d "$BACKEND_DIR" ]] || die "backend directory not found: $BACKEND_DIR"
    [[ -d "$FRONTEND_DIR" ]] || die "frontend directory not found: $FRONTEND_DIR"

    command -v pnpm >/dev/null 2>&1 || die "pnpm is not installed or not in PATH"
    command -v redis-cli >/dev/null 2>&1 || die "redis-cli is not installed or not in PATH"

    if [[ -d "$BACKEND_VENV_DIR" ]]; then
        [[ -x "$BACKEND_VENV_DIR/bin/python" ]] || die "backend venv exists but python is not executable: $BACKEND_VENV_DIR/bin/python"
        [[ -x "$BACKEND_VENV_DIR/bin/uvicorn" ]] || die "uvicorn is not installed in backend venv; run: cd backend && source venv/bin/activate && pip install -r requirements.txt"
        [[ -x "$BACKEND_VENV_DIR/bin/celery" ]] || die "celery is not installed in backend venv; run: cd backend && source venv/bin/activate && pip install -r requirements.txt"
    else
        command -v uvicorn >/dev/null 2>&1 || die "uvicorn is not available; create backend/venv or install backend requirements"
        command -v celery >/dev/null 2>&1 || die "celery is not available; create backend/venv or install backend requirements"
    fi
}

ensure_redis() {
    if [[ "$START_REDIS" == "0" || "$START_REDIS" == "false" ]]; then
        log "Redis check skipped"
        return 0
    fi

    if redis-cli ping >/dev/null 2>&1; then
        log "Redis: PONG"
        return 0
    fi

    command -v service >/dev/null 2>&1 || die "Redis is not running and service command is not available"
    command -v sudo >/dev/null 2>&1 || die "Redis is not running and sudo is not available"

    log "Redis is not running; starting redis-server with sudo"
    sudo service redis-server start
    sleep 1

    if redis-cli ping >/dev/null 2>&1; then
        log "Redis: PONG"
        return 0
    fi

    die "Redis did not respond to redis-cli ping after start"
}

prefix_output() {
    local name="$1"
    sed -u "s/^/[$name] /"
}

start_service() {
    local name="$1"
    local dir="$2"
    local cmd="$3"

    (
        cd "$dir"

        if [[ "$dir" == "$BACKEND_DIR" && -d "$BACKEND_VENV_DIR/bin" ]]; then
            export VIRTUAL_ENV="$BACKEND_VENV_DIR"
            export PATH="$BACKEND_VENV_DIR/bin:$PATH"
            export PYTHONPATH="$BACKEND_DIR${PYTHONPATH:+:$PYTHONPATH}"
        fi

        exec setsid bash -c "$cmd"
    ) > >(prefix_output "$name") 2>&1 &

    PIDS+=("$!")
    log "started $name"
}

cleanup() {
    local exit_code=$?

    trap - EXIT INT TERM

    if ((${#PIDS[@]} > 0)); then
        log "stopping services..."

        for pid in "${PIDS[@]}"; do
            if kill -0 "$pid" >/dev/null 2>&1; then
                kill -TERM "-$pid" >/dev/null 2>&1 || kill -TERM "$pid" >/dev/null 2>&1 || true
            fi
        done

        wait "${PIDS[@]}" >/dev/null 2>&1 || true
    fi

    exit "$exit_code"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

main() {
    load_env_file "$ROOT_DIR/.env"
    load_env_file "$BACKEND_DIR/.env"
    set_local_defaults
    check_requirements
    ensure_redis

    log "starting local development services"
    log "FastAPI:  http://localhost:${BACKEND_PORT}/docs"
    log "Frontend: http://localhost:${FRONTEND_PORT}"
    log "API proxy target: $VITE_API_PROXY_TARGET"
    if [[ -x "$BACKEND_VENV_DIR/bin/python" ]]; then
        log "Backend venv: $BACKEND_VENV_DIR"
    else
        log "Backend venv: not found; using commands from PATH"
    fi
    log "press Ctrl+C to stop all services"

    start_service "uvicorn" "$BACKEND_DIR" "$UVICORN_CMD"
    start_service "celery" "$BACKEND_DIR" "$CELERY_CMD"
    start_service "frontend" "$FRONTEND_DIR" "$FRONTEND_CMD"

    set +e
    wait -n "${PIDS[@]}"
    local status=$?
    set -e

    log "a service exited; shutting down the rest"
    return "$status"
}

main "$@"
