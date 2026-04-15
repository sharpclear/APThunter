#!/usr/bin/env bash
# 供宿主机 cron 调用：在 backend 容器内执行每日数据抓取（依赖镜像内已 COPY scripts/）
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"
LOG_DIR="$PROJECT_ROOT/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/get_dailydata.cron.log"
# 使用 docker compose V2；无 TTY，适合 cron
/usr/bin/docker compose exec -T backend python /app/scripts/get_dailydata.py >>"$LOG_FILE" 2>&1
