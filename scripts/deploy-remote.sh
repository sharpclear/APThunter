#!/usr/bin/env bash
# Load a packaged image archive on the remote VM, bootstrap the database,
# and recreate app containers from the loaded images.
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
  --migrations-only            Run database bootstrap/migration only; do not load images or recreate app containers
  --baseline-migrations        Kept for compatibility; database bootstrap now adopts covered legacy migrations automatically
  --run-untracked-migrations   Kept for compatibility; future unrecorded migrations are applied by database bootstrap
  --skip-health-check          Do not wait for service health after recreate
  -h, --help                   Show this help

Environment overrides:
  COMPOSE_PROJECT_NAME         Default: apthunter
  RUN_MIGRATIONS               Default: 1
  RUN_DB_BOOTSTRAP             Default: 1
  STOP_APP_BEFORE_MIGRATION    Default: 1
  PULL_EXTERNAL_IMAGES         Default: 1
  HEALTH_TIMEOUT_SEC           Default: 420
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
MIGRATIONS_ONLY=0
TARGET_IMAGES=()

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
    --migrations-only)
      MIGRATIONS_ONLY=1
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

compose() {
  docker compose -p "$COMPOSE_PROJECT_NAME" "$@"
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
  [[ -f "$archive" ]] || fail "image archive not found: $archive"

  verify_archive_checksum "$archive"

  log "loading Docker images from: $archive"
  gzip -dc "$archive" | docker load

  log "checking loaded Compose images"
  docker image inspect "${TARGET_IMAGES[@]}" >/dev/null
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
  log "starting infrastructure services without building"
  compose up -d --no-build mysql redis minio
  wait_for_service mysql "$HEALTH_TIMEOUT_SEC"
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
  log "recreating app services without building"
  compose up -d --no-build --force-recreate backend celery-worker frontend
}

verify_services() {
  if [[ "$SKIP_HEALTH_CHECK" == "1" ]]; then
    log "health check skipped"
    return
  fi

  local failed=0
  wait_for_service backend "$HEALTH_TIMEOUT_SEC" || failed=1
  wait_for_service celery-worker "$HEALTH_TIMEOUT_SEC" || failed=1
  wait_for_service frontend "$HEALTH_TIMEOUT_SEC" || failed=1

  log "current Compose status"
  compose ps

  if [[ "$failed" == "1" ]]; then
    fail "one or more services did not become healthy before timeout; no rollback was attempted"
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

  if ! docker compose version >/dev/null 2>&1; then
    fail "docker compose is required"
  fi

  log "project root: $ROOT"
  log "compose project: $COMPOSE_PROJECT_NAME"

  local archive=""
  local manifest_file=""
  if [[ "$MIGRATIONS_ONLY" != "1" ]]; then
    archive="$(resolve_archive)"
    manifest_file="$(resolve_manifest "$archive")"
    load_manifest_target_images "$manifest_file"
    load_image_archive "$archive"
  else
    load_manifest_target_images ""
  fi

  ensure_external_images
  ensure_infra_services

  if [[ "$STOP_APP_BEFORE_MIGRATION" == "1" && ( "$RUN_MIGRATIONS" == "1" || "$RUN_DB_BOOTSTRAP" == "1" ) ]]; then
    if [[ "$MIGRATIONS_ONLY" != "1" ]]; then
      log "stopping app services before database bootstrap"
      compose stop frontend celery-worker backend || true
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

  log "deployment complete"
}

main "$@"
