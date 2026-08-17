# Lazarus.day 事件采集 API 接入说明

## 实施前只读审计结论

- 现有入口为 `scripts/collect_lazarus_day.py`，内部调用
  `scripts.lazarus_day.cli.main`；Python 3.10 环境，采集依赖为 `httpx` 和
  `beautifulsoup4`；
- 增量入口为 `--since-last-success`。采集器以成功 checkpoint 中的报告日期和
  最近 URL 防止重复发现，批内及历史事件使用规范化链接、组织、日期、标题和
  event key 判重；详情失败时不推进 checkpoint，并保留失败产物；HTTP 客户端
  已有限次重试、退避、抖动和 `Retry-After` 处理；
- 产物位于 `data/events/{raw,normalized,review,reports,state}`，运行日志位于
  `logs/`。旧采集器不连接数据库；实施前已有每周任务
  `APTHunter-LazarusDay-Weekly` 和独立 checkpoint；
- 数据源实现只使用 HTTP/HTML，不包含浏览器、OCR、本地模型或 PDF 处理；
- 历史原始产物有 317 个互异来源记录。来源唯一键优先使用 lazarus.day 报告 URL
  中带平台后缀的完整 slug；无 slug 的已获取内容使用完整 SHA-256，失败抓取使用
  完整规范 URL SHA-256。禁止短哈希、标题、日期或文件名作为唯一键；
- 首次 API 索引排除 25 条明确非事件和 14 条精确重复，得到 278 个来源事件。
  一份来源报告的多组织拆分保留在 `structured_event.variants`，不会伪造多个来源
  ID。

## 1. 服务边界

该服务封装现有 Lazarus.day 采集器，不改写抓取、解析、组织匹配、判重和 checkpoint 逻辑。API 使用 FastAPI、单 worker Uvicorn、SQLite WAL 和持久任务队列。

- 监听地址固定为 `127.0.0.1:8788`；
- `/healthz` 公开，其他接口要求 `X-API-Key`；
- 密钥来自 `LAZARUS_DAY_API_KEY`，缺失时回退到 `EVENT_COLLECTOR_API_KEY`；
- 未配置密钥时，受保护接口返回 503；
- Swagger、ReDoc、OpenAPI 和通配 CORS 均关闭；
- API 只接受固定的 `incremental` 模式，不接受命令、路径、端口或模型参数；
- 原采集器文件锁和 SQLite 单 active run 约束共同防止并发采集；
- 不连接业务数据库，不修改两个参考 CSV。

本数据源没有 PDF、下载附件、OCR、浏览器或本地模型产物。因此提供 `/raw`、`/quality`、`/evidence`，不提供虚假的 PDF 或模型摘要接口。

## 2. 安装和启动

```powershell
cd 'F:\APT Hunter\EventCapture\Lazarus.day'
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-api.txt

$env:LAZARUS_DAY_API_KEY = '<至少32字节的随机密钥>'
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts\lazarus_day\start_api.ps1
```

只验证启动配置，不启动服务：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts\lazarus_day\start_api.ps1 -DryRun
```

SQLite 默认位于：

```text
data/events/state/api/lazarus-day-api.db
```

### 2.1 环境变量

- `LAZARUS_DAY_API_KEY`：必填的专用 API 密钥；未设置时读取
  `EVENT_COLLECTOR_API_KEY`，两者都缺失则除 `/healthz` 外一律返回 503；
- `LAZARUS_DAY_API_WORKER`：默认开启；仅在只读诊断或烟测时设为 `0`，
  正式部署不得关闭；
- `LAZARUS_DAY_API_POLL_SECONDS`、`LAZARUS_DAY_API_LEASE_SECONDS`、
  `LAZARUS_DAY_API_BUSY_RETRY_SECONDS`：任务轮询、worker 租约和文件锁冲突
  重试间隔，通常保持默认；
- `APTHUNTER_USER_AGENT`、`HTTP_PROXY`、`HTTPS_PROXY`：沿用原采集器的
  网络配置。

服务进程的 stdout/stderr 由部署它的服务管理器收集。采集子进程日志位于
`logs/api/`，每次原生采集产物位于
`data/events/api-runs/api-<32位十六进制>/`。

## 3. 主系统调用

### 3.1 存活与就绪

```powershell
Invoke-RestMethod http://127.0.0.1:8788/healthz
Invoke-RestMethod http://127.0.0.1:8788/readyz `
  -Headers @{'X-API-Key'=$env:LAZARUS_DAY_API_KEY}
```

### 3.2 提交增量任务

```powershell
$headers = @{
  'X-API-Key' = $env:LAZARUS_DAY_API_KEY
  'Idempotency-Key' = 'lazarus-day-2026-W33'
}
$run = Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8788/api/v1/runs `
  -Headers $headers -ContentType 'application/json' `
  -Body '{"mode":"incremental"}'
```

成功返回 202、任务 ID 和 `Location`。同一幂等键重放返回同一任务；已有其他 queued/running 任务时返回 409，并在错误体中返回已有任务 ID。

### 3.3 轮询任务及结果

```powershell
Invoke-RestMethod "http://127.0.0.1:8788/api/v1/runs/$($run.id)" `
  -Headers @{'X-API-Key'=$env:LAZARUS_DAY_API_KEY}
Invoke-RestMethod "http://127.0.0.1:8788/api/v1/runs/$($run.id)/events" `
  -Headers @{'X-API-Key'=$env:LAZARUS_DAY_API_KEY}
```

任务状态为 `queued`、`running`、`completed`、`completed_with_review` 或 `failed`。计数分别给出 `new`、`recovered`、`completed`、`completed_with_review`、`manual_review` 和 `failed`。

### 3.4 增量同步

首次调用：

```powershell
$page = Invoke-RestMethod `
  'http://127.0.0.1:8788/api/v1/events?limit=100' `
  -Headers @{'X-API-Key'=$env:LAZARUS_DAY_API_KEY}
```

保存 `next_cursor`，下次原样传回：

```powershell
$cursor = [Uri]::EscapeDataString($page.next_cursor)
$page = Invoke-RestMethod `
  "http://127.0.0.1:8788/api/v1/events?limit=100&cursor=$cursor" `
  -Headers @{'X-API-Key'=$env:LAZARUS_DAY_API_KEY}
```

游标由 SQLite 自增 change sequence、持久 instance ID 和 HMAC 构成。主系统应在当前页事务性入库成功后再保存 `next_cursor`，并以 `source + source_event_id` 为幂等唯一键，以 `version` 判断更新。

### 3.5 事件及证据

完整 `source_event_id` 必须进行 URL 编码，禁止短 ID：

```text
GET /api/v1/events/{source_event_id}
GET /api/v1/events/{source_event_id}/raw
GET /api/v1/events/{source_event_id}/quality
GET /api/v1/events/{source_event_id}/evidence
```

`/raw` 每次读取时验证数据库索引、目录 containment、JSONL 行 SHA-256、来源 ID 和页面内容 SHA-256。路径、绝对路径和短哈希均不能由调用方传入。

## 4. 事件契约和质量限制

每项至少返回 `source`、`source_event_id`、`version`、标题、描述、事件/报告时间、采集/更新时间、质量状态、审核标志、来源链接、结构化 variants、evidence、provenance 和产物 links。

Lazarus.day 的一条来源报告可能拆分为多个组织事件，这些拆分保存在 `structured_event.variants`。顶层组织字段只有在已接受 variants 唯一归属于同一组织时才填写。待复核数据可通过变更流同步，但必须依据 `quality_status` 和 `review_required` 隔离，不能直接展示。

首次启动从现有原始 JSONL、审核快照和参考事件表导入；明确被原采集器拒绝的非事件和精确重复不进入事件索引。同一产品摘要未变化时不增加版本或 change。

## 5. 旧计划任务切换

现有 `APTHunter-LazarusDay-Weekly` 任务在 API 验收期间保持不变。主系统完成以下检查后才能安全禁用旧任务：

1. API 以正式密钥连续运行至少两个周末；
2. 每次任务均完成，主系统保存并恢复游标；
3. `completed_with_review` 和 `manual_review` 已进入既有审核流程；
4. API checkpoint 和原生文件锁验证正常；
5. 运维方明确把调度归属切换到主系统。

切换时只禁用旧计划任务，不删除任务、checkpoint、日志或历史产物，便于回退。
