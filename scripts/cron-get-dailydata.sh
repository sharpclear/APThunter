#!/usr/bin/env bash
# 供宿主机 cron 调用：在 backend 容器内执行每日数据抓取。
# 直接把宿主机当前脚本通过 stdin 交给容器 Python，更新脚本后无需重建镜像。
# 自动任务只允许在北京时间 09:00 前开始，避免迟到数据引发延迟检测/推送。
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"
LOG_DIR="$PROJECT_ROOT/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/get_dailydata.cron.log"
CATCH_UP_DAYS="${WHOISDS_CATCHUP_DAYS:-14}"
BEIJING_HOUR="$(TZ=Asia/Shanghai date +%H)"

{
  printf '\n[%s] WhoisDS 自动采集开始（北京时间 %s:00）\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$BEIJING_HOUR"
  if ((10#$BEIJING_HOUR >= 9)); then
    echo "已达到北京时间 09:00，跳过本轮；不会执行迟到补采或触发推送"
    exit 0
  fi

  # 使用 docker compose V2；无 TTY，适合 cron。脚本只下载文件，不调用检测或通知接口。
  /usr/bin/docker compose exec -T backend \
    python - --catch-up-days "$CATCH_UP_DAYS" --max-start-hour 9 \
    <"$PROJECT_ROOT/backend/scripts/get_dailydata.py"
} >>"$LOG_FILE" 2>&1
