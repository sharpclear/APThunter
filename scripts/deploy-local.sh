#!/usr/bin/env bash
# Package existing local Docker images and upload the archive to the VM.
# Git operations are intentionally manual and are not handled here.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/deploy-local.sh [options]

Options:
  --tag TAG                 Deployment tag. Default: manual-YYYYMMDD-HHMMSS
  --source-project NAME     Local source image prefix. Default: auto
  --target-project NAME     Remote target image prefix. Default: apthunter
  --remote-host HOST        Remote host. Default: 192.168.32.219
  --remote-port PORT        Remote SSH port. Default: 22
  --remote-user USER        Remote SSH user. Default: mlz
  --remote-project-dir DIR  Remote APTHunter project directory. Default: /home/mlz/APTHunter
  --remote-upload-dir DIR   Remote upload directory. Default: /home/mlz/APTHunter/releases
  --ssh-key PATH            SSH private key path. Default: password login
  --output-dir DIR          Local output directory. Default: .deploy/TAG
  --no-upload               Package only; do not upload
  --dry-run                 Show selected image mapping; do not tag, save, or upload
  -h, --help                Show this help

Environment overrides:
  LOCAL_COMPOSE_PROJECT_NAME   Default: current directory name
  SOURCE_COMPOSE_PROJECT_NAME  Default: auto
  TARGET_COMPOSE_PROJECT_NAME  Default: apthunter

This script does not build images. Build and verify the images manually first.
In auto mode, each service uses the newest image found between LOCAL_COMPOSE_PROJECT_NAME-*, TARGET_COMPOSE_PROJECT_NAME-*, and the current local Compose container image.
EOF
}

log() {
  printf '[deploy-local] %s\n' "$*"
}

fail() {
  printf '[deploy-local] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

shell_quote() {
  local value="$1"
  printf "'%s'" "$(printf '%s' "$value" | sed "s/'/'\\\\''/g")"
}

compose_current_image() {
  local service="$1"
  docker compose ps --format json 2>/dev/null \
    | sed -n \
      -e "s/.*\"Image\":\"\\([^\"]*\\)\".*\"Service\":\"${service}\".*/\\1/p" \
      -e "s/.*\"Service\":\"${service}\".*\"Image\":\"\\([^\"]*\\)\".*/\\1/p" \
    | head -n 1
}

choose_source_image() {
  local service="$1"
  local candidates=()
  local candidate created
  local current_image=""
  local container_image_id=""
  local best_image=""
  local best_created=""

  if [[ "$SOURCE_COMPOSE_PROJECT_NAME" == "auto" ]]; then
    candidates+=("${LOCAL_COMPOSE_PROJECT_NAME}-${service}:latest")
    if [[ "$TARGET_COMPOSE_PROJECT_NAME" != "$LOCAL_COMPOSE_PROJECT_NAME" ]]; then
      candidates+=("${TARGET_COMPOSE_PROJECT_NAME}-${service}:latest")
    fi
    current_image="$(compose_current_image "$service" || true)"
    if [[ -n "$current_image" ]]; then
      candidates+=("$current_image")
    fi
    if container_image_id="$(docker container inspect -f '{{.Image}}' "apthunter-${service}" 2>/dev/null)"; then
      candidates+=("$container_image_id")
    fi
  else
    candidates+=("${SOURCE_COMPOSE_PROJECT_NAME}-${service}:latest")
  fi

  for candidate in "${candidates[@]}"; do
    if created="$(docker image inspect -f '{{.Created}}' "$candidate" 2>/dev/null)"; then
      if [[ -z "$best_image" || "$created" > "$best_created" ]]; then
        best_image="$candidate"
        best_created="$created"
      fi
    fi
  done

  [[ -n "$best_image" ]] || fail "missing local image for service $service; checked: ${candidates[*]}"
  printf '%s' "$best_image"
}

DEPLOY_TAG="${DEPLOY_TAG:-manual-$(date +%Y%m%d-%H%M%S)}"
REMOTE_HOST="${REMOTE_HOST:-192.168.32.219}"
REMOTE_PORT="${REMOTE_PORT:-22}"
REMOTE_USER="${REMOTE_USER:-mlz}"
REMOTE_PROJECT_DIR="${REMOTE_PROJECT_DIR:-/home/mlz/APTHunter}"
REMOTE_UPLOAD_DIR="${REMOTE_UPLOAD_DIR:-}"
SSH_KEY_LOCAL_PATH="${SSH_KEY_LOCAL_PATH:-password login}"
LOCAL_COMPOSE_PROJECT_NAME="${LOCAL_COMPOSE_PROJECT_NAME:-$(basename "$ROOT")}"
SOURCE_COMPOSE_PROJECT_NAME="${SOURCE_COMPOSE_PROJECT_NAME:-auto}"
TARGET_COMPOSE_PROJECT_NAME="${TARGET_COMPOSE_PROJECT_NAME:-${COMPOSE_PROJECT_NAME:-apthunter}}"
OUTPUT_DIR="${OUTPUT_DIR:-}"
UPLOAD="${UPLOAD:-1}"
DRY_RUN="${DRY_RUN:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      DEPLOY_TAG="${2:?--tag requires a value}"
      shift 2
      ;;
    --source-project)
      SOURCE_COMPOSE_PROJECT_NAME="${2:?--source-project requires a value}"
      shift 2
      ;;
    --target-project)
      TARGET_COMPOSE_PROJECT_NAME="${2:?--target-project requires a value}"
      shift 2
      ;;
    --remote-host)
      REMOTE_HOST="${2:?--remote-host requires a value}"
      shift 2
      ;;
    --remote-port)
      REMOTE_PORT="${2:?--remote-port requires a value}"
      shift 2
      ;;
    --remote-user)
      REMOTE_USER="${2:?--remote-user requires a value}"
      shift 2
      ;;
    --remote-project-dir)
      REMOTE_PROJECT_DIR="${2:?--remote-project-dir requires a value}"
      shift 2
      ;;
    --remote-upload-dir)
      REMOTE_UPLOAD_DIR="${2:?--remote-upload-dir requires a value}"
      shift 2
      ;;
    --ssh-key)
      SSH_KEY_LOCAL_PATH="${2:?--ssh-key requires a value}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:?--output-dir requires a value}"
      shift 2
      ;;
    --no-upload)
      UPLOAD=0
      shift
      ;;
    --dry-run)
      DRY_RUN=1
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

if [[ -z "$REMOTE_UPLOAD_DIR" ]]; then
  REMOTE_UPLOAD_DIR="$REMOTE_PROJECT_DIR/releases"
fi

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$ROOT/.deploy/$DEPLOY_TAG"
fi

case "$DEPLOY_TAG" in
  *[!A-Za-z0-9_.-]*)
    fail "DEPLOY_TAG may only contain letters, numbers, dot, underscore, and dash"
    ;;
esac

require_cmd docker
require_cmd gzip
require_cmd sha256sum
require_cmd sed
require_cmd date
require_cmd awk

if [[ "$UPLOAD" == "1" ]]; then
  require_cmd ssh
  require_cmd scp
  [[ -n "$REMOTE_HOST" ]] || fail "REMOTE_HOST is required when upload is enabled"
fi

mkdir -p "$OUTPUT_DIR"

services=(
  mysql
  backend
  celery-worker
  frontend
)

source_images=()
target_images=()
for service in "${services[@]}"; do
  source_images+=("$(choose_source_image "$service")")
  target_images+=("${TARGET_COMPOSE_PROJECT_NAME}-${service}:latest")
done

log "project root: $ROOT"
log "local image project: $LOCAL_COMPOSE_PROJECT_NAME"
log "source image project: $SOURCE_COMPOSE_PROJECT_NAME"
log "target image project: $TARGET_COMPOSE_PROJECT_NAME"
log "deployment tag: $DEPLOY_TAG"
log "remote project directory: $REMOTE_PROJECT_DIR"

if [[ "$DRY_RUN" == "1" ]]; then
  log "dry run selected image mapping"
  for i in "${!services[@]}"; do
    log "${services[$i]}: ${source_images[$i]} -> ${target_images[$i]}"
  done
  exit 0
fi

log "tagging source images with remote target names"
for i in "${!services[@]}"; do
  if [[ "${source_images[$i]}" != "${target_images[$i]}" ]]; then
    docker tag "${source_images[$i]}" "${target_images[$i]}"
  fi
  log "${services[$i]}: ${source_images[$i]} -> ${target_images[$i]}"
done

archive="$OUTPUT_DIR/apthunter-images-${DEPLOY_TAG}.tar.gz"
checksum_file="$archive.sha256"
manifest_file="$OUTPUT_DIR/manifest-${DEPLOY_TAG}.env"

log "saving image archive: $archive"
docker save "${target_images[@]}" | gzip -c > "$archive"

archive_sha256="$(sha256sum "$archive" | awk '{print $1}')"
printf '%s  %s\n' "$archive_sha256" "$(basename "$archive")" > "$checksum_file"

git_commit="unknown"
git_branch="unknown"
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git_commit="$(git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)"
  git_branch="$(git branch --show-current 2>/dev/null || printf unknown)"
fi

cat > "$manifest_file" <<EOF
DEPLOY_TAG=$DEPLOY_TAG
SOURCE_COMPOSE_PROJECT_NAME=$SOURCE_COMPOSE_PROJECT_NAME
TARGET_COMPOSE_PROJECT_NAME=$TARGET_COMPOSE_PROJECT_NAME
CREATED_AT=$(date -Iseconds)
LOCAL_PROJECT_ROOT=$ROOT
LOCAL_GIT_BRANCH=$git_branch
LOCAL_GIT_COMMIT=$git_commit
ARCHIVE=$(basename "$archive")
ARCHIVE_SHA256=$archive_sha256
SOURCE_IMAGES=${source_images[*]}
TARGET_IMAGES=${target_images[*]}
REMOTE_PROJECT_DIR=$REMOTE_PROJECT_DIR
REMOTE_UPLOAD_DIR=$REMOTE_UPLOAD_DIR
RUN_MIGRATIONS=1
ROLLBACK_ON_HEALTH_FAILURE=0
EOF

for image in "${source_images[@]}"; do
  image_id="$(docker image inspect -f '{{.Id}}' "$image")"
  printf 'IMAGE_ID_%s=%s\n' "$(printf '%s' "$image" | sed 's/[^A-Za-z0-9_]/_/g')" "$image_id" >> "$manifest_file"
done

log "wrote checksum: $checksum_file"
log "wrote manifest: $manifest_file"

if [[ "$UPLOAD" == "1" ]]; then
  ssh_opts=(-p "$REMOTE_PORT")
  scp_opts=(-P "$REMOTE_PORT")
  if [[ -n "$SSH_KEY_LOCAL_PATH" && "$SSH_KEY_LOCAL_PATH" != "password login" ]]; then
    ssh_opts+=(-i "$SSH_KEY_LOCAL_PATH")
    scp_opts+=(-i "$SSH_KEY_LOCAL_PATH")
  fi

  remote_target="${REMOTE_USER}@${REMOTE_HOST}"
  remote_dir_quoted="$(shell_quote "$REMOTE_UPLOAD_DIR")"

  log "creating remote upload directory: $remote_target:$REMOTE_UPLOAD_DIR"
  ssh "${ssh_opts[@]}" "$remote_target" "mkdir -p $remote_dir_quoted"

  log "uploading archive, checksum, and manifest"
  scp "${scp_opts[@]}" "$archive" "$checksum_file" "$manifest_file" "$remote_target:$REMOTE_UPLOAD_DIR/"

  cat <<EOF

Upload complete.

After you manually update code on the remote machine, run:

  ssh -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST
  cd $REMOTE_PROJECT_DIR
  ./scripts/deploy-remote.sh --tag $DEPLOY_TAG

EOF
else
  cat <<EOF

Package complete.

Archive:  $archive
Checksum: $checksum_file
Manifest: $manifest_file

EOF
fi
