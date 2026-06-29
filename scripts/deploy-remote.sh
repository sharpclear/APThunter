#!/usr/bin/env bash
# Load a packaged image archive on the remote VM, run existing DB migrations,
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
  --skip-migrations            Do not run SQL migration stage
  --skip-db-bootstrap          Do not run idempotent DB seed/fix stage
  --migrations-only            Run migration stage only; do not load images or recreate app containers
  --baseline-migrations        Record current migration SQL files as applied without executing them
  --run-untracked-migrations   If schema_migrations is missing, execute existing SQL files instead of baselining them
  --skip-health-check          Do not wait for service health after recreate
  -h, --help                   Show this help

Environment overrides:
  COMPOSE_PROJECT_NAME         Default: apthunter
  RUN_MIGRATIONS               Default: 1
  RUN_DB_BOOTSTRAP             Default: 1
  BASELINE_ON_MISSING_TABLE    Default: 1
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

mysql_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\'/\'\'}"
  printf '%s' "$value"
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

compose() {
  docker compose -p "$COMPOSE_PROJECT_NAME" "$@"
}

mysql_exec() {
  compose exec -T mysql sh -c 'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" "$MYSQL_DATABASE"'
}

mysql_query() {
  compose exec -T mysql sh -c 'mysql -N -B -uroot -p"$MYSQL_ROOT_PASSWORD" "$MYSQL_DATABASE" 2>/dev/null'
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

  local required_images=(
    "${COMPOSE_PROJECT_NAME}-mysql:latest"
    "${COMPOSE_PROJECT_NAME}-backend:latest"
    "${COMPOSE_PROJECT_NAME}-celery-worker:latest"
    "${COMPOSE_PROJECT_NAME}-frontend:latest"
  )

  log "checking loaded Compose images"
  docker image inspect "${required_images[@]}" >/dev/null
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

record_migration() {
  local filename="$1"
  local checksum="$2"
  local filename_sql checksum_sql
  filename_sql="$(mysql_escape "$filename")"
  checksum_sql="$(mysql_escape "$checksum")"

  printf "INSERT INTO schema_migrations (filename, checksum) VALUES ('%s', '%s') ON DUPLICATE KEY UPDATE checksum = VALUES(checksum);\n" \
    "$filename_sql" "$checksum_sql" | mysql_exec >/dev/null
}

run_migrations() {
  local migration_dir="$ROOT/backend/db/migrations"
  [[ -d "$migration_dir" ]] || {
    log "migration directory not found; skipping: $migration_dir"
    return
  }

  shopt -s nullglob
  local migration_files=("$migration_dir"/*.sql)
  shopt -u nullglob

  if [[ "${#migration_files[@]}" -eq 0 ]]; then
    log "no migration SQL files found"
    return
  fi

  log "preparing schema_migrations table"
  local had_table
  had_table="$(printf "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'schema_migrations';\n" | mysql_query | tr -d '[:space:]')"

  cat <<'SQL' | mysql_exec >/dev/null
CREATE TABLE IF NOT EXISTS schema_migrations (
  filename VARCHAR(255) NOT NULL PRIMARY KEY,
  checksum CHAR(64) NOT NULL,
  applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
SQL

  if [[ "$BASELINE_MIGRATIONS" == "1" || ( "$had_table" == "0" && "$BASELINE_ON_MISSING_TABLE" == "1" ) ]]; then
    if [[ "$BASELINE_MIGRATIONS" == "1" ]]; then
      log "baselining current migration files by request; SQL files will not be executed"
    else
      log "schema_migrations did not exist; baselining current migration files for existing DB"
    fi

    local file filename checksum
    for file in "${migration_files[@]}"; do
      filename="$(basename "$file")"
      checksum="$(sha256sum "$file" | awk '{print $1}')"
      record_migration "$filename" "$checksum"
      log "baselined migration: $filename"
    done
    return
  fi

  local file filename checksum filename_sql existing_checksum
  for file in "${migration_files[@]}"; do
    filename="$(basename "$file")"
    checksum="$(sha256sum "$file" | awk '{print $1}')"
    filename_sql="$(mysql_escape "$filename")"
    existing_checksum="$(printf "SELECT checksum FROM schema_migrations WHERE filename = '%s' LIMIT 1;\n" "$filename_sql" | mysql_query | tr -d '[:space:]' || true)"

    if [[ -n "$existing_checksum" ]]; then
      if [[ "$existing_checksum" != "$checksum" ]]; then
        fail "migration checksum changed after being applied: $filename"
      fi
      log "skipping already applied migration: $filename"
      continue
    fi

    if [[ "$filename" == "007_add_dga_detection_task.sql" ]]; then
      log "recording superseded legacy migration without executing: $filename"
      record_migration "$filename" "$checksum"
      continue
    fi

    log "applying migration: $filename"
    mysql_exec < "$file"
    record_migration "$filename" "$checksum"
  done
}

run_db_bootstrap() {
  log "running idempotent DB bootstrap"

  log "ensuring current model/task enums"
  cat <<'SQL' | mysql_exec >/dev/null
ALTER TABLE models
  MODIFY COLUMN model_category ENUM('malicious','impersonation','dga','history_similarity') DEFAULT NULL;

ALTER TABLE tasks
  MODIFY COLUMN task_type ENUM('malicious','impersonation','malicious_ip','dga','history_similarity') NOT NULL COMMENT '任务类型';

ALTER TABLE training_tasks
  MODIFY COLUMN model_category ENUM('malicious','impersonation','dga','history_similarity') NOT NULL DEFAULT 'malicious';

ALTER TABLE alerts
  MODIFY COLUMN task_type ENUM('malicious', 'impersonation', 'malicious_ip', 'dga', 'history_similarity') NOT NULL COMMENT '任务类型：恶意域名检测/仿冒域名检测/恶意IP检测/DGA域名检测/历史高度相似检测';

ALTER TABLE alert_files
  MODIFY COLUMN task_type ENUM('malicious', 'impersonation', 'malicious_ip', 'dga', 'history_similarity') NOT NULL COMMENT '任务类型';
SQL

  local seed_file="$ROOT/backend/db/init/05_seed_core_data.sql"
  [[ -f "$seed_file" ]] || fail "core seed SQL not found: $seed_file"
  log "seeding official users/models: $(basename "$seed_file")"
  mysql_exec < "$seed_file"

  local dga_switch_file="$ROOT/backend/db/migrations/009_switch_dga_binary_detector.sql"
  if [[ -f "$dga_switch_file" ]]; then
    log "ensuring DGA binary model metadata: $(basename "$dga_switch_file")"
    mysql_exec < "$dga_switch_file"
  else
    log "DGA switch migration not found; skipping: $dga_switch_file"
  fi

  log "granting active official models to all users"
  cat <<'SQL' | mysql_exec >/dev/null
INSERT INTO user_models (user_id, model_id, acquired_at, is_active, source)
SELECT u.id, m.id, NOW(), 1, 'official'
FROM users u
JOIN models m
  ON m.model_type = 'official'
 AND m.status = 'active'
WHERE NOT EXISTS (
  SELECT 1
  FROM user_models um
  WHERE um.user_id = u.id
    AND um.model_id = m.id
);
SQL

  log "verifying DGA official model"
  local dga_count
  dga_count="$(printf "SELECT COUNT(*) FROM models WHERE model_category = 'dga' AND model_type = 'official' AND status = 'active' AND model_path = 'saved_model/dga_binary_detector.joblib';\n" | mysql_query | tr -d '[:space:]')"
  [[ "$dga_count" != "0" ]] || fail "DGA official model is missing after DB bootstrap"
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
  if [[ "$MIGRATIONS_ONLY" != "1" ]]; then
    archive="$(resolve_archive)"
    load_image_archive "$archive"
  fi

  ensure_external_images
  ensure_infra_services

  if [[ "$RUN_MIGRATIONS" == "1" ]]; then
    if [[ "$STOP_APP_BEFORE_MIGRATION" == "1" && "$MIGRATIONS_ONLY" != "1" ]]; then
      log "stopping app services before migration"
      compose stop frontend celery-worker backend || true
    elif [[ "$STOP_APP_BEFORE_MIGRATION" == "1" ]]; then
      log "migrations-only mode; app services will not be stopped"
    fi
    run_migrations
  else
    log "migration stage skipped"
  fi

  if [[ "$RUN_DB_BOOTSTRAP" == "1" ]]; then
    run_db_bootstrap
  else
    log "DB bootstrap stage skipped"
  fi

  if [[ "$MIGRATIONS_ONLY" == "1" ]]; then
    log "migrations-only mode complete"
    return
  fi

  recreate_app_services
  verify_services

  log "deployment complete"
}

main "$@"
