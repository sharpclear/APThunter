# Qianxin 事件采集接入

## 拓扑

Qianxin 的 Playwright 登录态、本地模型和报告产物保留在 Windows 主机。Windows 上的 API 监听
`192.168.21.181:8787`，只允许 APTHunter 虚拟机 `192.168.32.219` 访问。Celery Worker 使用 API Key
拉取独立的 `apt_events` 变更流，先写入 `apt_event_candidates`，不让采集器直接连接 MySQL。

```text
Windows Qianxin collector/API (192.168.21.181:8787)
    -> APTHunter Celery Worker (192.168.32.219)
    -> apt_event_candidates, source=qianxin
    -> 结构校验/历史去重
    -> apt_events
```

虚拟机到 Windows 的就绪检查：

```bash
curl -fsS \
  -H "X-API-Key: $QIANXIN_API_KEY" \
  http://192.168.21.181:8787/readyz
```

## 虚拟机配置

在 APTHunter 根目录 `.env` 中配置：

```dotenv
QIANXIN_API_URL=http://192.168.21.181:8787
QIANXIN_API_KEY=与Windows用户环境中完全相同的64位密钥
QIANXIN_EVENT_SYNC_ENABLED=true
QIANXIN_COLLECTION_TRIGGER_ENABLED=false
QIANXIN_EVENT_AUTO_IMPORT=true
QIANXIN_EVENT_SYNC_INTERVAL_SEC=600
QIANXIN_EVENT_PAGE_LIMIT=100
QIANXIN_EVENT_MAX_PAGES_PER_SYNC=20
QIANXIN_EVENT_HTTP_TIMEOUT_SEC=30
```

当前使用直接导入模式：Qianxin 来源记录即使标记为 `needs_review`，也不再受来源审核状态和 0.75
置信度门槛阻挡。同步仍会校验日期、组织、链接、证据等结构字段，并执行事件键、链接、组织、日期和
标题去重；结构有效且不是重复项的记录直接写入 `apt_events`，同时保留来源 PDF SHA、版本和证据。

Windows 目前仍有 Qianxin 周期采集任务，因此 `QIANXIN_COLLECTION_TRIGGER_ENABLED=false`。如果以后明确由
APTHunter 接管采集调度，应先禁用 Windows 的重复采集计划任务，再将该变量改为 `true`。事件同步与采集
触发是两个独立开关。

## 启动

修改环境变量后重建需要读取配置的三个服务：

```bash
docker compose up -d --build backend celery-worker celery-beat
docker compose ps backend celery-worker celery-beat
docker compose logs --tail=100 backend celery-worker celery-beat
```

Celery Beat 默认每600秒投递一次 `tasks.sync_qianxin_events`。每次同步在事务提交后才保存不透明事件游标；
网络失败不会提前推进游标，重复执行由来源身份哈希幂等处理。

## 管理接口

以下接口要求 APTHunter 登录态：

- `GET /api/event-ingestion/qianxin/status`：Qianxin 游标、最近同步批次和候选数量；
- `GET /api/event-ingestion/qianxin/candidates?decision=needs_review`：查看审核候选；
- `POST /api/event-ingestion/qianxin/sync`：立即拉取已经生成的事件；
- `POST /api/event-ingestion/qianxin/trigger`：让 Windows API 启动一次增量采集。

前端事件时间线无需修改。直接导入成功后，Qianxin 事件会按现有 `apt_events` 查询逻辑展示。

## 验收

```bash
docker compose exec celery-worker python -c \
  "from app.tasks.qianxin_event_tasks import _client; print(_client().ready())"

docker compose exec celery-worker celery -A app.celery_app:celery_app inspect registered
```

注册任务应包含 `tasks.sync_qianxin_events` 和 `tasks.trigger_qianxin_collection`。首次同步后，检查：

```sql
SELECT source, decision, COUNT(*)
FROM apt_event_candidates
WHERE source = 'qianxin'
GROUP BY source, decision;
```

直接导入模式下，结构有效的新记录预期为 `auto_imported`，并在 `apt_events` 中存在对应事件。
