#!/usr/bin/env bash
# 最小联调/验收：Compose 状态 + 入口与 API 可达性（需在宿主机执行，且 stack 已 up）
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=== docker compose ps ==="
docker compose ps

echo "=== frontend (nginx) http://127.0.0.1/ ==="
curl -sfS -o /dev/null -w "HTTP %{http_code}\n" "http://127.0.0.1/" || {
  echo "提示: 若 80 未映射到本机或仅绑定非 loopback，请改 URL 或 compose ports。"
  exit 1
}

echo "=== backend docs http://127.0.0.1:8000/docs（默认仅本机映射）==="
if curl -sfS -o /dev/null -w "HTTP %{http_code}\n" "http://127.0.0.1:8000/docs"; then
  :
else
  echo "（跳过或失败：可能未暴露 8000 或非本机执行）"
fi

echo "=== 经 nginx 反代探测 /api/docs（与 FastAPI 路由前缀一致时应为 200）==="
curl -sfS -o /dev/null -w "HTTP %{http_code}\n" "http://127.0.0.1/api/docs" || echo "（404 时若 :8000/docs 正常，多为 API 未使用 /api 前缀，属路由配置问题非 Compose）"

echo "=== 完成 ==="
