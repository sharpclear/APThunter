#!/usr/bin/env bash
# Load a packaged image archive on the remote VM, bootstrap the database,
# and recreate only the application containers from the loaded images.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/deploy-remote.sh [options]

Options:
  --tag TAG                    Use releases/apthunter-images-TAG.tar.gz
  --archive FILE               Use a specific image archive
  --upload-dir DIR             Directory containing uploaded archives. Default: ./releases
  --skip-migrations            Do not apply unrecorded migration files
  --skip-db-bootstrap          Do not apply current seed data
  --skip-db-backup             Do not create a compressed MySQL backup before migrations
  --migrations-only            Run database bootstrap/migration only; do not load images or recreate app containers
  --allow-code-mismatch        Allow manifest and remote Git commits to differ
  --allow-active-tasks         Allow deployment while APTHunter/Lazarus tasks are active
  --baseline-migrations        Kept for compatibility; database bootstrap now adopts covered legacy migrations automatically
  --run-untracked-migrations   Kept for compatibility; future unrecorded migrations are applied by database bootstrap
  --skip-health-check          Skip final verification (staged startup readiness checks still run)
  -h, --help                   Show this help

Environment overrides:
  COMPOSE_PROJECT_NAME         Default: apthunter
  RUN_MIGRATIONS               Default: 1
  RUN_DB_BOOTSTRAP             Default: 1
  STOP_APP_BEFORE_MIGRATION    Default: 1
  PULL_EXTERNAL_IMAGES         Default: 1
  HEALTH_TIMEOUT_SEC           Default: 420
  DB_BACKUP_DIR                Default: ./backups
EOF
}

log() {
  printf '[deploy-remote] %s\n' "$*"
}

fail() {
  printf '[deploy-remote] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-apthunter}"
UPLOAD_DIR="${REMOTE_UPLOAD_DIR:-$ROOT/releases}"
DEPLOY_TAG="${DEPLOY_TAG:-}"
ARCHIVE="${ARCHIVE:-}"
RUN_MIGRATIONS="${RUN_MIGRATIONS:-1}"
RUN_DB_BOOTSTRAP="${RUN_DB_BOOTSTRAP:-1}"
BASELINE_MIGRATIONS="${BASELINE_MIGRATIONS:-0}"
BASELINE_ON_MISSING_TABLE="${BASELINE_ON_MISSING_TABLE:-1}"
STOP_APP_BEFORE_MIGRATION="${STOP_APP_BEFORE_MIGRATION:-1}"
PULL_EXTERNAL_IMAGES="${PULL_EXTERNAL_IMAGES:-1}"
HEALTH_TIMEOUT_SEC="${HEALTH_TIMEOUT_SEC:-420}"
SKIP_HEALTH_CHECK="${SKIP_HEALTH_CHECK:-0}"
CREATE_DB_BACKUP="${CREATE_DB_BACKUP:-1}"
DB_BACKUP_DIR="${DB_BACKUP_DIR:-$ROOT/backups}"
ALLOW_CODE_MISMATCH="${ALLOW_CODE_MISMATCH:-0}"
ALLOW_ACTIVE_TASKS="${ALLOW_ACTIVE_TASKS:-0}"
MIGRATIONS_ONLY=0
TARGET_IMAGES=()
APP_SERVICES=(backend celery-worker celery-beat lazarus-collector frontend)
ROLLBACK_TAG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      DEPLOY_TAG="${2:?--tag requires a value}"
      shift 2
      ;;
    --archive)
      ARCHIVE="${2:?--archive requires a value}"
      shift 2
      ;;
    --upload-dir)
      UPLOAD_DIR="${2:?--upload-dir requires a value}"
      shift 2
      ;;
    --skip-migrations)
      RUN_MIGRATIONS=0
      shift
      ;;
    --skip-db-bootstrap)
      RUN_DB_BOOTSTRAP=0
      shift
      ;;
    --skip-db-backup)
      CREATE_DB_BACKUP=0
      shift
      ;;
    --migrations-only)
      MIGRATIONS_ONLY=1
      shift
      ;;
    --allow-code-mismatch)
      ALLOW_CODE_MISMATCH=1
      shift
      ;;
    --allow-active-tasks)
      ALLOW_ACTIVE_TASKS=1
      shift
      ;;
    --baseline-migrations)
      BASELINE_MIGRATIONS=1
      shift
      ;;
    --run-untracked-migrations)
      BASELINE_ON_MISSING_TABLE=0
      shift
      ;;
    --skip-health-check)
      SKIP_HEALTH_CHECK=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

if [[ "$BASELINE_MIGRATIONS" == "1" ]]; then
  log "--baseline-migrations is kept for compatibility; current bootstrap adopts covered legacy migrations automatically"
fi

if [[ "$BASELINE_ON_MISSING_TABLE" == "0" ]]; then
  log "--run-untracked-migrations is kept for compatibility; future unrecorded migrations are applied automatically"
fi

if [[ -n "$DEPLOY_TAG" ]]; then
  case "$DEPLOY_TAG" in
    *[!A-Za-z0-9_.-]*)
      fail "DEPLOY_TAG may only contain letters, numbers, dot, underscore, and dash"
      ;;
  esac
fi

compose() {
  docker compose -p "$COMPOSE_PROJECT_NAME" "$@"
}

manifest_value() {
  local manifest_file="$1"
  local key="$2"
  sed -n "s/^${key}=//p" "$manifest_file" | tail -n 1
}

effective_env_value() {
  local key="$1"
  local value=""

  if [[ -n "${!key+x}" ]]; then
    value="${!key}"
  elif [[ -f "$ROOT/.env" ]]; then
    value="$(sed -n "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//p" "$ROOT/.env" | tail -n 1)"
    value="${value%$'\r'}"
    if [[ ${#value} -ge 2 ]]; then
      if [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]] \
        || [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
        value="${value:1:${#value}-2}"
      fi
    fi
  fi

  printf '%s' "$value"
}

is_true() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

validate_runtime_config() {
  log "validating Compose configuration"
  compose config --quiet

  if [[ "$MIGRATIONS_ONLY" == "1" ]]; then
    return
  fi

  local lazarus_key qianxin_enabled qianxin_url qianxin_key
  lazarus_key="$(effective_env_value LAZARUS_DAY_API_KEY)"
  [[ ${#lazarus_key} -ge 32 ]] \
    || fail "LAZARUS_DAY_API_KEY must be configured with at least 32 characters in .env"

  qianxin_enabled="$(effective_env_value QIANXIN_EVENT_SYNC_ENABLED)"
  if is_true "$qianxin_enabled"; then
    qianxin_url="$(effective_env_value QIANXIN_API_URL)"
    qianxin_key="$(effective_env_value QIANXIN_API_KEY)"
    [[ "$qianxin_url" == http://* || "$qianxin_url" == https://* ]] \
      || fail "QIANXIN_API_URL must be an http(s) URL when QIANXIN_EVENT_SYNC_ENABLED=true"
    [[ ${#qianxin_key} -ge 32 ]] \
      || fail "QIANXIN_API_KEY must contain at least 32 characters when QIANXIN_EVENT_SYNC_ENABLED=true"
  fi
}

verify_code_matches_manifest() {
  local manifest_file="$1"
  if [[ -z "$manifest_file" || ! -f "$manifest_file" ]]; then
    log "manifest not found; Git commit alignment cannot be verified"
    return
  fi

  local expected_commit actual_commit
  expected_commit="$(manifest_value "$manifest_file" LOCAL_GIT_COMMIT)"
  if [[ -z "$expected_commit" || "$expected_commit" == "unknown" ]]; then
    log "manifest has no Git commit; code alignment cannot be verified"
    return
  fi

  if ! command -v git >/dev/null 2>&1 || ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if [[ "$ALLOW_CODE_MISMATCH" == "1" ]]; then
      log "warning: remote directory is not a Git worktree; code mismatch explicitly allowed"
      return
    fi
    fail "cannot verify remote code against manifest; pass --allow-code-mismatch only after manual verification"
  fi

  actual_commit="$(git rev-parse --short=12 HEAD)"
  if [[ "$actual_commit" != "$expected_commit" ]]; then
    if [[ "$ALLOW_CODE_MISMATCH" == "1" ]]; then
      log "warning: code mismatch explicitly allowed (manifest=$expected_commit remote=$actual_commit)"
      return
    fi
    fail "code/image mismatch: manifest commit=$expected_commit, remote commit=$actual_commit; update the VM code first"
  fi
  if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    if [[ "$ALLOW_CODE_MISMATCH" == "1" ]]; then
      log "warning: tracked files are modified on the VM; code mismatch explicitly allowed"
    else
      fail "tracked files are modified on the VM; commit/stash them or use --allow-code-mismatch after manual verification"
    fi
  fi
  log "remote code matches image manifest commit: $actual_commit"
}

service_state() {
  local service="$1"
  local cid
  cid="$(compose ps -q "$service" 2>/dev/null || true)"
  if [[ -z "$cid" ]]; then
    printf 'missing'
    return 1
  fi
  docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid"
}

wait_for_service() {
  local service="$1"
  local timeout="${2:-$HEALTH_TIMEOUT_SEC}"
  local deadline=$((SECONDS + timeout))
  local state="unknown"

  while (( SECONDS < deadline )); do
    state="$(service_state "$service" || true)"
    case "$state" in
      healthy|running)
        log "$service is $state"
        return 0
        ;;
      exited|dead)
        log "$service is $state"
        return 1
        ;;
    esac
    sleep 5
  done

  log "$service did not become healthy before timeout; last state: $state"
  return 1
}

resolve_archive() {
  if [[ -n "$ARCHIVE" ]]; then
    printf '%s' "$ARCHIVE"
    return
  fi

  if [[ -n "$DEPLOY_TAG" ]]; then
    printf '%s/apthunter-images-%s.tar.gz' "$UPLOAD_DIR" "$DEPLOY_TAG"
    return
  fi

  local latest=""
  latest="$(find "$UPLOAD_DIR" -maxdepth 1 -type f -name 'apthunter-images-*.tar.gz' -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk 'NR == 1 {print $2}')"
  [[ -n "$latest" ]] || fail "no image archive found in $UPLOAD_DIR"
  printf '%s' "$latest"
}

resolve_manifest() {
  local archive="$1"
  if [[ -n "$DEPLOY_TAG" && -f "$UPLOAD_DIR/manifest-${DEPLOY_TAG}.env" ]]; then
    printf '%s' "$UPLOAD_DIR/manifest-${DEPLOY_TAG}.env"
    return
  fi

  local archive_dir archive_base tag_from_archive
  archive_dir="$(dirname "$archive")"
  archive_base="$(basename "$archive")"
  tag_from_archive="${archive_base#apthunter-images-}"
  tag_from_archive="${tag_from_archive%.tar.gz}"
  if [[ "$tag_from_archive" != "$archive_base" && -f "$archive_dir/manifest-${tag_from_archive}.env" ]]; then
    printf '%s' "$archive_dir/manifest-${tag_from_archive}.env"
    return
  fi

  printf ''
}

load_manifest_target_images() {
  local manifest_file="$1"
  TARGET_IMAGES=()
  if [[ -z "$manifest_file" || ! -f "$manifest_file" ]]; then
    log "manifest not found; falling back to Compose project image names"
    TARGET_IMAGES=(
      "${COMPOSE_PROJECT_NAME}-mysql:latest"
      "${COMPOSE_PROJECT_NAME}-backend:latest"
      "${COMPOSE_PROJECT_NAME}-celery-worker:latest"
      "${COMPOSE_PROJECT_NAME}-celery-beat:latest"
      "${COMPOSE_PROJECT_NAME}-lazarus-collector:latest"
      "${COMPOSE_PROJECT_NAME}-frontend:latest"
    )
    return
  fi

  local value
  value="$(sed -n 's/^TARGET_IMAGES=//p' "$manifest_file" | tail -n 1)"
  if [[ -z "$value" ]]; then
    fail "manifest exists but TARGET_IMAGES is empty: $manifest_file"
  fi
  read -r -a TARGET_IMAGES <<< "$value"
  log "loaded target images from manifest: $manifest_file"
}

verify_archive_checksum() {
  local archive="$1"
  local checksum_file="$archive.sha256"

  if [[ ! -f "$checksum_file" ]]; then
    log "checksum file not found; skipping checksum verification: $checksum_file"
    return
  fi

  log "verifying checksum: $checksum_file"
  (cd "$(dirname "$archive")" && sha256sum -c "$(basename "$checksum_file")")
}

load_image_archive() {
  local archive="$1"
  local manifest_file="$2"
  [[ -f "$archive" ]] || fail "image archive not found: $archive"

  verify_archive_checksum "$archive"

  log "loading Docker images from: $archive"
  gzip -dc "$archive" | docker load

  log "checking loaded Compose images"
  docker image inspect "${TARGET_IMAGES[@]}" >/dev/null

  local target_platform="linux/amd64"
  if [[ -n "$manifest_file" && -f "$manifest_file" ]]; then
    target_platform="$(manifest_value "$manifest_file" TARGET_PLATFORM)"
    target_platform="${target_platform:-linux/amd64}"
  fi

  local image actual_platform
  for image in "${TARGET_IMAGES[@]}"; do
    actual_platform="$(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$image")"
    [[ "$actual_platform" == "$target_platform" ]] \
      || fail "loaded image $image has platform $actual_platform; expected $target_platform"
  done
  log "loaded image platform verified: $target_platform"
}

ensure_external_images() {
  if [[ "$PULL_EXTERNAL_IMAGES" != "1" ]]; then
    return
  fi

  log "pulling external images: redis, minio"
  if compose pull redis minio; then
    return
  fi

  log "external image pull failed; checking whether required images already exist locally"
  docker image inspect redis:7-alpine minio/minio:latest >/dev/null
}

ensure_infra_services() {
  log "ensuring infrastructure services are running without recreating existing containers"
  compose up -d --no-build --no-recreate mysql redis minio
  wait_for_service mysql "$HEALTH_TIMEOUT_SEC"
}

mysql_scalar() {
  local query="$1"
  local cid
  cid="$(compose ps -q mysql)"
  [[ -n "$cid" ]] || fail "mysql container is not available"
  docker exec "$cid" sh -c \
    'exec mysql -N -B -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -e "$1"' \
    sh "$query"
}

mysql_table_exists() {
  local table="$1"
  local count
  count="$(mysql_scalar "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='${table}';")"
  [[ "$count" == "1" ]]
}

check_active_tasks() {
  if [[ "$ALLOW_ACTIVE_TASKS" == "1" ]]; then
    log "warning: active-task protection was explicitly disabled"
    return
  fi

  local active=0 count=0
  if mysql_table_exists tasks; then
    count="$(mysql_scalar "SELECT COUNT(*) FROM tasks WHERE status='processing';")"
    active=$((active + count))
  fi
  if mysql_table_exists training_tasks; then
    count="$(mysql_scalar "SELECT COUNT(*) FROM training_tasks WHERE training_status='training';")"
    active=$((active + count))
  fi
  [[ "$active" == "0" ]] \
    || fail "$active APTHunter task(s) are processing/training; wait for completion or pass --allow-active-tasks"

  local collector_cid collector_active
  collector_cid="$(compose ps -q lazarus-collector 2>/dev/null || true)"
  if [[ -n "$collector_cid" ]] \
    && [[ "$(docker inspect -f '{{.State.Running}}' "$collector_cid" 2>/dev/null || true)" == "true" ]]; then
    if ! collector_active="$(docker exec "$collector_cid" python -c 'import json, os, urllib.request; key=os.environ["LAZARUS_DAY_API_KEY"]; req=urllib.request.Request("http://127.0.0.1:8788/api/v1/runs?limit=200", headers={"X-API-Key": key}); data=json.load(urllib.request.urlopen(req, timeout=10)); print(sum(item.get("status") in {"queued", "running"} for item in data.get("items", [])))')"; then
      fail "could not verify Lazarus collector activity; use --allow-active-tasks only after checking it manually"
    fi
    [[ "$collector_active" == "0" ]] \
      || fail "$collector_active Lazarus collection run(s) are queued/running; wait for completion or pass --allow-active-tasks"
  fi

  log "no active APTHunter or Lazarus tasks detected"
}

backup_database() {
  if [[ "$CREATE_DB_BACKUP" != "1" || ( "$RUN_MIGRATIONS" != "1" && "$RUN_DB_BOOTSTRAP" != "1" ) ]]; then
    log "database backup skipped"
    return
  fi

  mkdir -p "$DB_BACKUP_DIR"
  local backup_stamp backup_file partial_file cid
  backup_stamp="${DEPLOY_TAG:-manual}-$(date +%Y%m%d-%H%M%S)"
  backup_file="$DB_BACKUP_DIR/apthunter-before-${backup_stamp}.sql.gz"
  partial_file="${backup_file}.partial"
  [[ ! -e "$backup_file" && ! -e "$partial_file" ]] \
    || fail "database backup target already exists: $backup_file"
  cid="$(compose ps -q mysql)"
  [[ -n "$cid" ]] || fail "mysql container is not available for backup"

  log "creating pre-deployment database backup: $backup_file"
  docker exec "$cid" sh -c \
    'exec mysqldump --single-transaction --quick --skip-lock-tables --no-tablespaces -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"' \
    | gzip -c > "$partial_file"
  [[ -s "$partial_file" ]] || fail "database backup is empty: $partial_file"
  mv "$partial_file" "$backup_file"
  log "database backup complete"
}

snapshot_current_images() {
  ROLLBACK_TAG="${DEPLOY_TAG:-$(date +%Y%m%d-%H%M%S)}"
  local service cid image_id rollback_image saved=0

  for service in "${APP_SERVICES[@]}"; do
    cid="$(compose ps -q "$service" 2>/dev/null || true)"
    [[ -n "$cid" ]] || continue
    image_id="$(docker inspect -f '{{.Image}}' "$cid")"
    rollback_image="${COMPOSE_PROJECT_NAME}-${service}:rollback-${ROLLBACK_TAG}"
    if docker image inspect "$rollback_image" >/dev/null 2>&1; then
      log "preserving existing rollback image: $rollback_image"
      saved=1
      continue
    fi
    docker tag "$image_id" "$rollback_image"
    log "saved rollback image: $rollback_image"
    saved=1
  done

  if [[ "$saved" == "0" ]]; then
    ROLLBACK_TAG=""
    log "no running application images were available for rollback tags"
  fi
}

show_rollback_hint() {
  [[ -n "$ROLLBACK_TAG" ]] || return
  log "rollback images use tag rollback-$ROLLBACK_TAG"
  log "to restore them, retag each available rollback image as :latest and recreate: ${APP_SERVICES[*]}"
}

run_db_bootstrap() {
  if [[ "$RUN_MIGRATIONS" != "1" && "$RUN_DB_BOOTSTRAP" != "1" ]]; then
    log "database bootstrap skipped"
    return
  fi

  local args=()
  if [[ "$RUN_MIGRATIONS" != "1" ]]; then
    args+=(--skip-migrations)
  fi
  if [[ "$RUN_DB_BOOTSTRAP" != "1" ]]; then
    args+=(--skip-seed)
  fi

  log "running image-contained database bootstrap"
  compose run --rm -T --no-deps --pull never backend python /app/scripts/db_bootstrap.py "${args[@]}"
}

recreate_app_services() {
  log "recreating app services without building or touching dependencies"
  compose up -d --no-build --no-deps --force-recreate backend lazarus-collector
  wait_for_service backend "$HEALTH_TIMEOUT_SEC" \
    || { show_rollback_hint; fail "backend failed during staged application startup"; }
  wait_for_service lazarus-collector "$HEALTH_TIMEOUT_SEC" \
    || { show_rollback_hint; fail "lazarus-collector failed during staged application startup"; }

  compose up -d --no-build --no-deps --force-recreate celery-worker frontend
  wait_for_service celery-worker "$HEALTH_TIMEOUT_SEC" \
    || { show_rollback_hint; fail "celery-worker failed during staged application startup"; }
  wait_for_service frontend "$HEALTH_TIMEOUT_SEC" \
    || { show_rollback_hint; fail "frontend failed during staged application startup"; }

  compose up -d --no-build --no-deps --force-recreate celery-beat
}

verify_services() {
  if [[ "$SKIP_HEALTH_CHECK" == "1" ]]; then
    log "health check skipped"
    return
  fi

  local failed=0
  wait_for_service backend "$HEALTH_TIMEOUT_SEC" || failed=1
  wait_for_service celery-worker "$HEALTH_TIMEOUT_SEC" || failed=1
  wait_for_service celery-beat "$HEALTH_TIMEOUT_SEC" || failed=1
  wait_for_service lazarus-collector "$HEALTH_TIMEOUT_SEC" || failed=1
  wait_for_service frontend "$HEALTH_TIMEOUT_SEC" || failed=1

  log "current Compose status"
  compose ps

  if [[ "$failed" == "1" ]]; then
    show_rollback_hint
    fail "one or more services did not become healthy before timeout; no automatic rollback was attempted"
  fi

  if [[ -x "$ROOT/scripts/compose-verify.sh" ]]; then
    log "running endpoint verification"
    "$ROOT/scripts/compose-verify.sh"
  fi
}

main() {
  require_cmd docker
  require_cmd gzip
  require_cmd sha256sum
  require_cmd find
  require_cmd sort
  require_cmd awk
  require_cmd sed
  require_cmd tail

  if ! docker compose version >/dev/null 2>&1; then
    fail "docker compose is required"
  fi

  log "project root: $ROOT"
  log "compose project: $COMPOSE_PROJECT_NAME"

  validate_runtime_config

  local archive=""
  local manifest_file=""
  if [[ "$MIGRATIONS_ONLY" != "1" ]]; then
    archive="$(resolve_archive)"
    manifest_file="$(resolve_manifest "$archive")"
    load_manifest_target_images "$manifest_file"
    verify_code_matches_manifest "$manifest_file"
  else
    load_manifest_target_images ""
  fi

  ensure_external_images
  local existing_mysql=""
  existing_mysql="$(compose ps -q --all mysql 2>/dev/null || true)"

  if [[ -n "$existing_mysql" ]]; then
    # Start an existing database before loading a new mysql:latest tag.  The
    # --no-recreate path below keeps the current database container untouched.
    ensure_infra_services
    check_active_tasks
    backup_database
    if [[ "$MIGRATIONS_ONLY" != "1" ]]; then
      snapshot_current_images
      load_image_archive "$archive" "$manifest_file"
    fi
  else
    if [[ "$MIGRATIONS_ONLY" == "1" ]]; then
      fail "migrations-only mode requires an existing mysql container"
    fi
    log "no existing mysql container found; treating this as a first deployment"
    snapshot_current_images
    load_image_archive "$archive" "$manifest_file"
    ensure_infra_services
    check_active_tasks
    log "pre-deployment database backup skipped because the database is new"
  fi

  if [[ "$STOP_APP_BEFORE_MIGRATION" == "1" && ( "$RUN_MIGRATIONS" == "1" || "$RUN_DB_BOOTSTRAP" == "1" ) ]]; then
    if [[ "$MIGRATIONS_ONLY" != "1" ]]; then
      log "stopping app services before database bootstrap"
      compose stop frontend celery-beat celery-worker backend lazarus-collector || true
    else
      log "migrations-only mode; app services will not be stopped"
    fi
  fi

  run_db_bootstrap

  if [[ "$MIGRATIONS_ONLY" == "1" ]]; then
    log "migrations-only mode complete"
    return
  fi

  recreate_app_services
  verify_services

  show_rollback_hint
  log "deployment complete"
}

main "$@"
