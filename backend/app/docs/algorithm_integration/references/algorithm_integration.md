# algorithm_integration 参考文档

本文是 APTHunter 新算法接入的执行检查表。文字面向 Codex 使用，目标是避免漏接手动检测、订阅预警、数据库结构和初始化脚本。

## 1. 接入前必须确认的信息

开始写代码前，先从用户描述或算法材料里整理以下信息：

- 算法中文名。
- 稳定标识 `algorithm_key`，使用小写 snake_case。
- 是否新增业务类型；如果不新增，复用哪个 `model_category` / `task_type`。
- 检测对象：域名、IP、URL 或其他。
- 支持的数据源：上传文件、新注册域名、手动输入。
- 上传文件格式和列名要求。
- 订阅是否支持；订阅默认数据源是否为每日新注册域名。
- 是否需要官方域名文件、白名单、参考样本库或其他辅助文件。
- 模型路径，按容器内 `backend/app/models` 相对路径描述，例如 `saved_model/example.joblib`。
- 新增 Python 依赖和环境变量。
- 是否调用外部网络、LLM 或第三方服务；必须有超时、重试上限、日志和无 Key 降级策略。
- 算法输入、输出、Excel 工作表、`statistics` 字段和逐条风险记录字段。
- 高风险判定规则。
- `threshold=NULL` 时的默认预警策略。
- 前端 0-100 自定义阈值如何映射为算法分数。
- 风险等级枚举和通知附件展示字段。
- 最小验收样例：输入、期望高风险结果、期望统计、失败样例。

如果高风险规则或阈值映射不清楚，必须先问用户。不能为了推进代码而自行定义业务语义。

## 2. 是否新增业务类型

优先复用已有类型。当前常见类型：

| 标识 | 用途 |
| --- | --- |
| `malicious` | 恶意域名检测 |
| `impersonation` | 仿冒域名检测 |
| `dga` | DGA 域名检测 |
| `history_similarity` | 历史高度相似检测 |

判断规则：

- 仅替换模型文件，且输入输出、高风险规则与现有类型一致：复用现有类型，只更新模型记录或适配器。
- 输出字段或预警规则不同，但页面和业务名仍属于现有类型：复用类型，扩展结果解析和筛选逻辑。
- 检测对象、页面、任务名、订阅类型和预警展示都需要独立语义：新增 `model_category` 和 `task_type`。

新增类型时，必须同步后端枚举、数据库枚举、初始化 SQL、migration、前端类型和通知展示。

## 3. 推荐算法适配器

优先新增：

```text
backend/app/models/<algorithm_key>_detection.py
```

推荐入口：

```python
def predict_from_file(
    file_content: bytes,
    filename: str,
    model_path: str | None = None,
    **options,
) -> tuple[bytes, dict, list[dict]]:
    """返回 Excel bytes、statistics、逐条风险记录。"""


def predict_from_domains(
    domains: list[str],
    source_label: str,
    model_path: str | None = None,
    **options,
) -> tuple[bytes, dict, list[dict]]:
    """返回 Excel bytes、statistics、逐条风险记录。"""
```

适配器只做算法和结果格式转换，不直接操作数据库、MinIO、FastAPI 请求对象或 Celery。业务副作用留在 `backend/app/services` 或 API 层。

逐条风险记录建议包含：

```json
{
  "domain": "example.com",
  "risk_score": 0.91,
  "risk_level": "high",
  "is_high_risk": true,
  "reason": "命中原因"
}
```

如果检测对象不是域名，字段可以是 `ip`、`url` 或其他明确名称，但预警归档、通知和前端展示也要同步适配。

## 4. 手动创建检测任务流程

用户在检测页面创建一次性任务时，通常经过：

```text
frontend/src/pages/detection/*
  -> backend/app/api/detection.py
  -> tasks 表
  -> backend/app/services/task_dispatcher.py
  -> backend/app/tasks/detection_tasks.py
  -> backend/app/services/task_executor.py
  -> MinIO results 桶
  -> tasks.extra
```

必须检查的文件：

- `backend/app/api/detection.py`
  - 新增或复用创建任务接口。
  - 校验 `dataSource`、文件类型、文件大小、日期范围、手动输入。
  - 上传文件到 MinIO，并写 `files` 记录。
  - 查询 `models`，校验 `user_models` 权限。
  - 创建 `Task`，`status='pending'`。
  - 调用 dispatcher 投递 Celery。
  - 入队失败时把任务标记为 `failed`，并在 `extra` 写入错误信息。
- `backend/app/services/task_dispatcher.py`
  - 新增对应 `dispatch_<algorithm_key>_task()`。
- `backend/app/tasks/detection_tasks.py`
  - 新增 Celery task，设置合理的重试策略。
- `backend/app/services/task_executor.py`
  - 查询 Task 和 Model。
  - 幂等处理已完成任务。
  - 根据 `dataSource` 读取上传文件、每日新注册域名或手动输入。
  - 调用算法适配器。
  - 上传 Excel 结果到 `results` 桶。
  - 更新 `tasks.extra`：`result_file_key`、`result_bucket`、`result_filename`、`statistics`、`completed_at`、`progress`、算法元数据。
  - 异常时将任务状态改为 `failed`，写入 `error`。
- `backend/app/api/detection.py` 的任务列表、结果查看和下载接口
  - 任务类型中文名。
  - 非 Excel 或特殊结果 JSON 的读取逻辑。
  - 前端任务详情需要的字段。

如果支持新注册域名，复用现有每日数据路径约定：

```text
{DAILY_DATA_DIR}/{YYYY-MM}/{YYYY-MM-DD}-domain.zip
```

如果支持手动输入，复用已有域名解析校验能力，或明确新增对象类型的解析规则。

## 5. 订阅和预警流程

订阅和预警主要在：

```text
backend/app/api/subscription.py
```

当前订阅调度是 APScheduler，同步执行 `execute_subscription()`，不是 Celery。接入新算法时不能只接一次性检测。

必须检查：

- `get_subscribable_models()`
  - 新模型是否能出现在可订阅模型列表。
  - `_model_category_to_subscription_type()` 是否返回前端可识别类型。
- `create_subscription()`
  - 是否需要官方文件或参考文件。
  - 阈值 `threshold` 和 `useCustomThreshold` 语义是否正确。
  - 文件上传时是否写 `files`。
- `execute_subscription()`
  - 按频率计算日期范围。
  - 收集每日新注册域名。
  - 调用对应算法适配器。
  - 创建 `Task`，写 `subscription_id`、`dateRange`、`statistics` 和算法元数据。
  - 上传完整检测结果。
  - 按高风险规则提取 `high_risk_domains` 或高风险对象。
  - 满足触发条件时创建 `Alert`。
  - 无高风险结果时仍应把任务标为 `completed`，并更新 `next_run_at`。
  - 异常时要回滚事务，并避免订阅卡死。
- 预警归档
  - `build_alert_result_json()` 是否能容纳新算法字段。
  - `save_alert_result_json_to_minio()` 是否写入 `files`。
  - `create_alert_file_mapping()` 是否允许新 `task_type`。
  - 归档失败时是否补偿删除 MinIO 孤儿对象，并将任务标记为 failed。
- 预警通知
  - `backend/app/services/notification/alert_notifier.py`
  - `backend/app/services/notification/email_service.py`
  - `backend/app/services/notification/feishu_service.py`
  - 摘要、附件、飞书卡片字段是否适配。
  - 通知失败不得阻塞订阅主流程或导致无限重试。

高风险结果提取要优先使用算法适配器返回的逐条风险记录，避免从 Excel 中脆弱解析。确实需要解析 Excel 时，要兼容列名缺失和空值。

## 6. 数据库交互

必须理解并检查这些表：

- `models`：模型名称、路径、分类、状态、官方/公开属性。
- `user_models`：用户可用模型授权。
- `files`：上传文件、结果文件、预警 JSON 文件的对象存储索引。
- `tasks`：一次性任务和订阅执行任务。
- `subscriptions`：订阅配置、频率、阈值、下次执行时间。
- `alerts`：预警摘要。
- `alert_files`：预警业务 ID 到完整结果文件的映射。
- `alert_domain_matches`：预警对象与组织关联结果，若使用组织归因需检查。

数据库交互要求：

- SQL 使用参数绑定，不拼接用户输入。
- 事务边界清晰；文件已上传但数据库失败时，需要考虑补偿或明确记录失败。
- `Task.status` 流转保持 `pending -> processing -> completed/failed`。
- `Subscription.next_run_at` 在正常执行、无数据、异常情况下都要合理更新，避免卡死。
- 已有数据库不能依赖重建数据卷，结构变化必须提供 migration。
- 大 JSON 不应参与排序或高频查询；列表页尽量只读轻量字段。

## 7. 数据库结构和初始化脚本

如果是全新业务类型，必须同步以下位置。

数据库初始化脚本：

- `backend/db/init/01_schema.sql`
  - `models.model_category`
  - `training_tasks.model_category`
  - `tasks.task_type`
  - `alerts.task_type`
  - `alert_files.task_type`
- `backend/db/init/05_seed_core_data.sql`
  - 新增官方模型种子数据。
  - 绑定默认管理员与官方模型。
  - `model_path` 必须与容器内真实路径一致。

已有数据库迁移：

- 新增 `backend/db/migrations/<next>_add_<algorithm_key>_detection_task.sql`。
- migration 要幂等或至少可安全重复检查。
- MySQL ENUM 修改要覆盖当前所有合法值，不能丢失旧值。
- 如果新增表，添加必要索引、外键和注释。

SQLAlchemy 实体：

- `backend/app/entities/model.py`
- `backend/app/entities/task.py`
- `backend/app/entities/alert_file.py`
- `backend/app/api/subscription.py` 内本地定义的 `Alert.task_type` 枚举。
- 其他直接声明枚举的实体或服务。

不要只改 `backend/db/init/*.sql`。已有 MySQL 数据卷不会自动重放初始化脚本。

## 8. 前端需要检查的地方

如果用户要求或新业务类型需要页面入口，检查：

- `frontend/src/router/dynamic-routes.ts`
  - 新检测页面路由和菜单。
- `frontend/src/pages/detection/<algorithm-key>-detection/index.vue`
  - 表单字段、数据源、上传文件、日期范围、手动输入、阈值设置。
- `frontend/src/pages/detection/alert/index.vue`
  - `SubscriptionModelType`
  - 类型标签。
  - 阈值默认说明。
  - 官方文件或参考文件上传逻辑。
  - 订阅列表和预警列表展示。
- `frontend/src/pages/detection/mytask/*`
  - 任务类型中文名。
  - 结果查看和下载。
- `frontend/src/api`
  - 如果新增接口封装，URL 写相对 `/api` 的路径，不要写成 `/api/...` 后再被 `baseURL=/api` 叠加。

前端文案使用中文，保持 Ant Design Vue、Pinia、组合式 API 和现有页面风格。

## 9. 依赖、配置和部署

后端依赖：

- 新增依赖写入 `backend/requirements.txt`。
- `requirements_all.txt` 只有在项目需要全量依赖同步时才改。
- 如果依赖需要系统库或模型文件，检查 `backend/Dockerfile` 和 `docker-compose.yml`。

配置：

- 新增环境变量要更新相关说明文档或 `.env` 示例，不写真实密钥。
- 网络和 LLM 调用必须支持超时、重试上限、日志、无 Key 降级。

模型和数据：

- 小模型可按仓库规则放置；大模型、训练数据、每日数据 zip、日志、缓存不要提交。
- `backend/app/models/saved_model` 会被 Compose 挂载到容器 `/app/app/models/saved_model`。
- 不要挂载或覆盖整个 `backend/app/models` 目录。

## 10. 验证清单

按改动范围选择最小验证。

后端基础检查：

```bash
cd backend
PYTHONPATH=. python -m py_compile app/api/detection.py app/api/subscription.py app/services/task_executor.py app/services/task_dispatcher.py app/tasks/detection_tasks.py
```

如果能连接服务和依赖：

```bash
docker compose ps
docker compose logs -f backend
docker compose logs -f celery-worker
```

前端检查：

```bash
cd frontend
pnpm typecheck
pnpm lint
```

数据库检查：

- 新增业务类型时，确认 init SQL、migration、SQLAlchemy 枚举值一致。
- 对已有数据库，确认 migration 能执行，不要求重建数据卷。
- 检查新官方模型是否进入 `models`，并绑定到 `user_models`。

功能验收：

- 一次性检测能创建任务，任务完成后能下载或查看结果。
- 上传文件、新注册域名、手动输入按接入卡声明工作。
- 订阅能创建，`next_run_at` 合理。
- 手动触发订阅检查后能创建订阅任务。
- 满足高风险规则时，`alerts`、`files`、`alert_files` 都有记录。
- `/api/alerts` 和 `/api/alerts/{alert_id}` 能读取新算法预警结果。
- 邮件/飞书配置缺失时不无限重试；配置存在时关键字段能展示。

## 11. 最终回复格式

最终回复要简洁列出：

- 改了什么。
- 关键文件路径。
- 执行了哪些验证命令及结果。
- 哪些验证因为环境限制未执行。
- 仍需用户提供或确认的事项，例如模型文件、生产环境 migration 执行、外部 API Key。
