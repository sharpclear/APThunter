# 奇安信 APT 采集 API 接入说明

该服务把现有的“增量抓取 → PDF 解析 → 本地模型摘要”流水线封装成异步 HTTP API。
业务系统不需要安装或直接调用本地模型，只需提交任务、轮询状态，并按完整 SHA-256 同步报告。
模型由 API 按需启动并作为唯一共享 `llama-server` 运行时保留；奇安信摘要任务和
Lazarus 结构化补全都复用该进程，不会同时加载两份 Qwen3-4B。

## 1. 安装与启动

在项目根目录执行：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-api.txt

# 请替换为随机生成的长密钥，不要提交到代码库。
$env:QIANXIN_API_KEY = '<replace-with-a-long-random-secret>'

.\.venv\Scripts\python.exe -m uvicorn scripts.qianxin.api:app `
  --host 0.0.0.0 `
  --port 8787 `
  --workers 1
```

也可以先设置密钥，再运行固定单 worker 的启动脚本：

```powershell
.\scripts\qianxin\start_api_service.ps1
```

默认数据库为 `data/state/api/qianxin-api.db`。首次启动会校验并导入现有的 PDF、merged document、
summary 和 quality 产物；当前 83 份历史报告会形成初始变更流。

服务默认要求 `QIANXIN_API_KEY`。只有 `/healthz` 是公开的存活探针，其余接口都需：

```http
X-API-Key: <secret>
```

开发期如确需关闭鉴权，可显式设置 `QIANXIN_API_REQUIRE_KEY=false`，但不能在跨主机部署时这样做。

### 1.1 内网虚拟机调用

Qianxin 流水线仍在本地 Windows 运行，Linux 虚拟机通过内网 API 调用。启动脚本
默认绑定 `0.0.0.0`，使本机周任务可通过 loopback 管理共享模型，同时让虚拟机
通过固定内网 IP 访问。必须用 Windows 防火墙把 TCP 8787 的来源限制为本机和
APTHunter 虚拟机，不得映射到公网：

```powershell
$env:QIANXIN_API_KEY = '<使用随机生成的长密钥>'
.\scripts\qianxin\start_api_service.ps1 `
  -HostAddress 0.0.0.0 `
  -Port 8787 `
  -PublicBaseUrl http://192.168.1.20:8787
```

Windows 防火墙应只允许 APTHunter 虚拟机的内网 IP 访问 TCP 8787。虚拟机验证命令：

```bash
curl -fsS \
  -H "X-API-Key: $QIANXIN_API_KEY" \
  http://192.168.1.20:8787/readyz
```

`QIANXIN_PUBLIC_BASE_URL` 只用于在原始报告链接缺失时生成可由虚拟机访问的 PDF API 链接，不应包含 API Key。

事件自动接受默认关闭（`QIANXIN_EVENT_AUTO_ACCEPT=false`）。这是有意的安全门：旧的奇安信事件可能已经以不同标题或链接进入 APTHunter，不能只靠字段精确相等判断没有重复。虚拟机可以直接拉取完整事件候选，但默认先进入审核/去重队列。只有主系统已经按来源 SHA、组织、日期和相似标题完成历史去重后，才可在启动前显式设置 `$env:QIANXIN_EVENT_AUTO_ACCEPT='true'`。

## 2. 主系统调用流程

### 2.0 共享模型与 Lazarus 补全

以下接口和其他 API 一样要求 `X-API-Key`：

```http
GET  /api/v1/model/status
POST /api/v1/model/ensure
POST /api/v1/model/lazarus/enrich
```

`ensure` 只会启动仓库中固定的 llama.cpp 和
`data/models/llm/Qwen3-4B-Q4_K_M.gguf`，不接受客户端传入模型路径、端口或命令。
Lazarus 请求最多包含 50000 字符来源正文及其 SHA-256；响应只返回中文标题、
描述、受控威胁类型、Actor 候选、事实点和逐项证据引文。服务会拒绝无法在来源
正文中定位的引文、Actor 名称和内部审核措辞，虚拟机采集器还会独立复核一次。

`run_weekly_incremental.ps1` 会先调用本机的 `model/ensure`，随后直接复用 8091
上的受管运行时。管理 API 不可用且 8091 空闲时才回退为旧的单批次启动/关闭；
端口被未知进程占用时仍会拒绝复用。

### 2.1 提交增量采集

```http
POST /api/v1/runs
X-API-Key: <secret>
Idempotency-Key: scheduler-2026-W33
Content-Type: application/json

{"mode":"incremental"}
```

返回 `202 Accepted` 和 `Location`：

```json
{
  "id": "6ff7d4c9bf93471ca712895798ca3576",
  "mode": "incremental",
  "status": "queued",
  "links": {
    "self": "/api/v1/runs/6ff7d4c9bf93471ca712895798ca3576",
    "reports": "/api/v1/runs/6ff7d4c9bf93471ca712895798ca3576/reports"
  }
}
```

同一调度周期应复用相同 `Idempotency-Key`。网络重试不会创建第二个任务；若另一个不同任务已经
排队或运行，接口返回 `409 run_already_active`。请求不能传命令、脚本路径、模型路径或端口。

### 2.2 轮询任务

```http
GET /api/v1/runs/{run_id}
X-API-Key: <secret>
```

终态为：

- `completed`：流水线成功且没有待复核新增项；
- `completed_with_review`：流水线成功，但部分结果经过过滤或需要分析员复核；
- `failed`：出现技术失败，可查看 `error` 并由下一次运行恢复；
- `queued` / `running`：继续轮询。

本地包装器的独占锁冲突不会误报完成；任务会保持排队并延迟重试。

### 2.3 增量同步结果

首次调用：

```http
GET /api/v1/reports?limit=100
X-API-Key: <secret>
```

保存响应中的 `next_cursor`，下次原样传回：

```http
GET /api/v1/reports?limit=100&cursor=<next_cursor>
```

游标基于 SQLite 追加序列并带 HMAC，不依赖文件时间、报告日期或 8 位 SHA 前缀。报告更新后会以
新 change 再次出现。主系统以完整 64 位 `sha256` 做幂等主键，并保存自身成功提交后的游标。

每份报告提供：

- `GET /api/v1/reports/{sha256}`：索引元数据；
- `GET /api/v1/reports/{sha256}/summary`：结构化摘要及 IOC；
- `GET /api/v1/reports/{sha256}/quality`：证据定位、过滤和质量信息；
- `GET /api/v1/reports/{sha256}/pdf`：原 PDF。

服务只接受完整 SHA，不接受本地路径。PDF 下载前会再次做目录边界和文件内容 SHA-256 校验。

### 2.4 APTHunter `apt_events` 兼容事件流

主系统不需要自行解析 PDF 摘要。使用独立事件游标调用：

```http
GET /api/v1/events?limit=100
X-API-Key: <secret>
```

后续把响应中的 `next_cursor` 原样传回：

```http
GET /api/v1/events?limit=100&cursor=<event_cursor>
```

`description` 由 API 保证为完整句子。适配器会拆分中英文分号，并为缺少句末标点的语句补充中文句号；
调用方不应再对该字段做二次补句号处理。

报告游标和事件游标作用域不同，不能混用。响应包含：

```json
{
  "schema_version": "apthunter.apt_events.v1",
  "auto_accept_enabled": false,
  "columns": ["id", "event_key", "event_date", "date_precision", "title"],
  "items": [
    {
      "source": "qianxin",
      "source_event_id": "<完整PDF SHA-256>",
      "version": 1,
      "quality_status": "needs_review",
      "review_required": true,
      "apt_event": {
        "id": null,
        "event_key": "<64位稳定键>",
        "event_date": "2026-08-12",
        "date_precision": "publication_date",
        "title": "报告标题",
        "description": "由带页码证据的关键发现组成",
        "link": "https://ti.qianxin.com/...",
        "event_type": "normal",
        "threat_type": "钓鱼攻击",
        "releasing_product": "报告发布厂商",
        "region": null,
        "latitude": null,
        "longitude": null,
        "organization_id": 40,
        "severity": 4,
        "confidence": 0.88,
        "review_status": "needs_review",
        "evidence": [],
        "collection_notes": null,
        "created_at": null
      }
    }
  ],
  "next_cursor": "<opaque cursor>",
  "has_more": false
}
```

单条查询：

```http
GET /api/v1/events/{完整PDF_SHA256}
X-API-Key: <secret>
```

事件转换规则：

- 一份报告生成一条事件候选，`id=null`，由 APTHunter 数据库分配 ID；
- PDF SHA-256 是来源身份，`event_key` 按链接、组织、日期和规范化标题生成；
- 描述只使用经过质量校验且能定位到 PDF 页码的关键发现；
- 威胁类型映射到 APTHunter 受控词表；无法确定时使用 `APT攻击` 并进入审核；
- `ready_with_filtered_items`、缺日期/组织/链接/页码证据、或可能包含多个活动的报告均设为 `needs_review`；
- 自动接受默认关闭，因此即使内容质量门通过也先返回 `needs_review`；启用 `QIANXIN_EVENT_AUTO_ACCEPT=true` 后，只有没有其他审核原因的候选才会成为 `accepted`；
- 后续采集会保存页面“发布厂商”列；历史元数据缺失时使用“奇安信威胁情报中心”并写入 `collection_notes`。

调用方必须先持久化候选和来源 SHA，完成自身事务后才能保存事件游标。不要把 `needs_review` 记录直接写入正式展示表。

## 3. 推荐的业务入库策略

1. 把 `sha256` 设为来源报告的唯一键。
2. 保存 `version`；同 SHA 的更高版本表示解析、摘要或校验结果有更新。
3. 原样保存 `evidence_quote` 与 `evidence_pages`，供界面回链原 PDF。
4. `review_required=true` 或 `quality_status != ready` 时进入分析员复核队列。
5. `indicators` 中只有 `observable` 适合作为高优先级候选，但仍不应未经确认直接下发封禁；
   `candidate` 与 `reference` 只用于调查上下文。
6. 当前结构化归因、目标和漏洞尚没有完整的 claim-to-quote 语义蕴含模型，属于分析草稿，
   不应无人工确认直接对外发布。

## 4. 调度归属

目前 Windows 计划任务仍保留为每周日 03:00 的兜底运行。API 和计划任务共享同一个跨进程锁，
不会同时修改流水线。如果主系统正式接管每周调度，应在完成一次 API 生产验收后禁用
`QianxinAPTWeeklyIncremental`，避免重复探测和不必要的排队重试。

跨主机部署时，建议用反向代理提供 TLS，仅允许主系统 IP 访问，并让服务运行在能够读取现有
Playwright 登录 profile 的同一 Windows 账户下。Uvicorn 必须保持单 worker；SQLite 原子任务认领
与 PowerShell 文件锁会形成两层并发保护。

## 5. 运维检查

```http
GET /healthz
GET /readyz
```

`/readyz` 会检查数据库、包装器、报告目录和首次产物索引。日志位于 `logs/api/`，原生任务清单位于
`data/state/weekly-incremental-runs/`。API 响应不会暴露这些绝对路径。

离线回归测试：

```powershell
.\.venv\Scripts\python.exe -m pytest
```

测试使用 fake runner，不会启动真实浏览器、下载器、MinerU 或本地模型。
