#!/usr/bin/env bash

# APTHunter local development launcher.
# Starts Redis, FastAPI/Uvicorn, Celery, and Vite for local development.

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
BACKEND_VENV_DIR="$BACKEND_DIR/venv"

DOTENV_OVERRIDE="${DOTENV_OVERRIDE:-0}"
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
        if [[ "$DOTENV_OVERRIDE" != "1" && -v "$key" ]]; then
            continue
        fi

        if [[ "$value" == \"*\" && "$value" == *\" ]]; then
            value="${value:1:${#value}-2}"
        elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
            value="${value:1:${#value}-2}"
        fi

        export "$key=$value"
    done < "$env_file"

    log "loaded env: ${env_file#$ROOT_DIR/}"
}

init_env() {
    BACKEND_PORT="${BACKEND_PORT:-8001}"
    FRONTEND_PORT="${FRONTEND_PORT:-6678}"
    START_REDIS="${START_REDIS:-1}"

    export MINIO_ENDPOINT="${MINIO_ENDPOINT:-localhost:9000}"
    export MINIO_ACCESS_KEY="${MINIO_ACCESS_KEY:-minioadmin}"
    export MINIO_SECRET_KEY="${MINIO_SECRET_KEY:-123456789}"
    export MINIO_BUCKET="${MINIO_BUCKET:-uploads}"

    export MYSQL_URL="${MYSQL_URL:-mysql+pymysql://apthunter:4CyUhr2zu6!@127.0.0.1:3307/apthunter_new}"
    export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
    export CELERY_BROKER_URL="${CELERY_BROKER_URL:-$REDIS_URL}"
    export CELERY_RESULT_BACKEND="${CELERY_RESULT_BACKEND:-$REDIS_URL}"

    export VITE_API_PROXY_TARGET="${VITE_API_PROXY_TARGET:-http://127.0.0.1:${BACKEND_PORT}}"
    export VITE_ENABLE_H3_MOCK="${VITE_ENABLE_H3_MOCK:-false}"

    UVICORN_CMD="${UVICORN_CMD:-python -m uvicorn app.main:app --host 0.0.0.0 --port ${BACKEND_PORT}}"
    CELERY_CMD="${CELERY_CMD:-python -m celery -A celery_worker worker --loglevel=info}"
    FRONTEND_CMD="${FRONTEND_CMD:-pnpm exec vite --host 0.0.0.0 --port ${FRONTEND_PORT} --strictPort}"
}

repair_venv_paths() {
    local activate_file="$BACKEND_VENV_DIR/bin/activate"
    [[ -f "$activate_file" ]] || return 0

    if grep -q "/backend/venv" "$activate_file" && ! grep -q "VIRTUAL_ENV=$BACKEND_VENV_DIR" "$activate_file"; then
        sed -i "s|VIRTUAL_ENV=.*backend/venv|VIRTUAL_ENV=$BACKEND_VENV_DIR|" "$activate_file" || true
        log "repaired backend venv activate path"
    fi

    local script shebang
    for script in "$BACKEND_VENV_DIR/bin"/pip "$BACKEND_VENV_DIR/bin"/pip3 "$BACKEND_VENV_DIR/bin"/pip3.10 "$BACKEND_VENV_DIR/bin"/uvicorn "$BACKEND_VENV_DIR/bin"/celery; do
        [[ -f "$script" ]] || continue
        IFS= read -r shebang < "$script" || true
        [[ "$shebang" == '#!'*python* ]] || continue
        [[ "$shebang" == "#!$BACKEND_VENV_DIR/bin/python" ]] && continue
        [[ "$shebang" == *"/backend/venv/"* ]] || continue
        sed -i "1s|^#!.*$|#!$BACKEND_VENV_DIR/bin/python|" "$script" || true
    done
}

check_basic_commands() {
    [[ -d "$BACKEND_DIR" ]] || die "backend directory not found: $BACKEND_DIR"
    [[ -d "$FRONTEND_DIR" ]] || die "frontend directory not found: $FRONTEND_DIR"
    [[ -f "$BACKEND_VENV_DIR/bin/activate" ]] || die "backend venv not found: $BACKEND_VENV_DIR"
    [[ -x "$BACKEND_VENV_DIR/bin/python" ]] || die "backend venv python is not executable: $BACKEND_VENV_DIR/bin/python"

    command -v pnpm >/dev/null 2>&1 || die "pnpm is not installed or not in PATH"
    command -v redis-cli >/dev/null 2>&1 || die "redis-cli is not installed or not in PATH"
}

redis_ready() {
    redis-cli -u "$REDIS_URL" ping >/dev/null 2>&1 || redis-cli ping >/dev/null 2>&1
}

ensure_redis() {
    if [[ "$START_REDIS" == "0" || "$START_REDIS" == "false" ]]; then
        log "Redis check skipped"
        return 0
    fi

    if redis_ready; then
        log "Redis: PONG"
        return 0
    fi

    if command -v redis-server >/dev/null 2>&1; then
        log "starting redis-server"
        redis-server --daemonize yes >/dev/null 2>&1 || true
        sleep 1
        if redis_ready; then
            log "Redis: PONG"
            return 0
        fi
    fi

    if command -v service >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
        log "starting redis-server with sudo service"
        sudo service redis-server start
        sleep 1
        if redis_ready; then
            log "Redis: PONG"
            return 0
        fi
    fi

    die "Redis is not running; start it manually or set START_REDIS=0"
}

prefix_output() {
    local name="$1"
    sed -u "s/^/[$name] /"
}

start_backend_service() {
    local name="$1"
    local cmd="$2"

    (
        cd "$BACKEND_DIR"
        # shellcheck disable=SC1091
        source "$BACKEND_VENV_DIR/bin/activate"
        export VIRTUAL_ENV="$BACKEND_VENV_DIR"
        export PATH="$BACKEND_VENV_DIR/bin:$PATH"
        export PYTHONPATH="$BACKEND_DIR${PYTHONPATH:+:$PYTHONPATH}"
        exec setsid bash -c "$cmd"
    ) > >(prefix_output "$name") 2>&1 &

    PIDS+=("$!")
    log "started $name"
}

start_frontend_service() {
    (
        cd "$FRONTEND_DIR"
        exec setsid bash -c "$FRONTEND_CMD"
    ) > >(prefix_output "frontend") 2>&1 &

    PIDS+=("$!")
    log "started frontend"
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
    init_env
    repair_venv_paths
    check_basic_commands
    ensure_redis

    log "starting APTHunter local development services"
    log "FastAPI:  http://127.0.0.1:${BACKEND_PORT}/docs"
    log "Frontend: http://127.0.0.1:${FRONTEND_PORT}"
    log "Backend venv: $BACKEND_VENV_DIR"
    log "press Ctrl+C to stop all services"

    start_backend_service "uvicorn" "$UVICORN_CMD"
    start_backend_service "celery" "$CELERY_CMD"
    start_frontend_service

    set +e
    wait -n "${PIDS[@]}"
    local status=$?
    set -e

    log "a service exited; shutting down the rest"
    return "$status"
}

main "$@"
