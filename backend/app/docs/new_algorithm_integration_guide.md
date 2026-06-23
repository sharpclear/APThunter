# 新算法接入检测、订阅与预警流程协作指南

本文面向研发新算法的成员。成员负责把算法能力、模型文件、输入输出契约和验收样例说明清楚；实际系统代码由 Codex 按本文提示词完成。

## 先判断接入类型

不要一上来就新增 `task_type` 或数据库枚举。先判断新算法属于哪一种：

1. **只是替换或新增同类模型**：输入、输出和高风险规则与现有恶意检测一致时，优先复用 `malicious` 分类，只新增模型记录和模型文件路径。
2. **同类检测但输出规则不同**：仍可复用现有分类，但需要 Codex 增加算法适配器、结果解析和预警筛选逻辑。
3. **新的业务检测类型**：例如新的域名风险类型、IP 风险类型、URL 风险类型，且页面、任务、订阅、预警展示都需要独立名称时，才新增 `model_category` / `task_type`。

当前已存在的业务类型有：

| 标识 | 用途 |
| --- | --- |
| `malicious` | 恶意域名检测 |
| `impersonation` | 仿冒域名检测 |
| `dga` | DGA 域名检测 |
| `history_similarity` | 历史高度相似检测 |

## 现有链路速览

一次性检测流程：

```text
frontend/src/pages/detection/*
  -> backend/app/api/detection.py 创建 Task
  -> backend/app/services/task_dispatcher.py 投递 Celery
  -> backend/app/tasks/detection_tasks.py Celery 任务入口
  -> backend/app/services/task_executor.py 执行算法
  -> MinIO results 桶保存 Excel 结果
  -> tasks.extra 写入 result_file_key / statistics / completed_at
```

订阅和预警流程：

```text
frontend/src/pages/detection/alert/index.vue
  -> backend/app/api/subscription.py 创建 Subscription
  -> APScheduler 到期执行 execute_subscription()
  -> 读取每日新注册域名数据
  -> 执行算法并创建 Task
  -> 按高风险规则创建 Alert
  -> build_alert_result_json() 组装完整预警 JSON
  -> MinIO + files + alert_files 归档
  -> dispatch_alert_notifications() 发送邮件/飞书
```

注意：一次性检测走 Celery；订阅检测目前在 `execute_subscription()` 内同步执行。接入新算法时两条链路都要检查。

## 成员必须做的操作

### 1. 填写算法接入卡

把下面模板填完整后交给 Codex。字段不清楚时先写“不支持”或“待定”，不要让 Codex 猜关键业务规则。

```text
算法中文名：
算法稳定标识 algorithm_key（小写 snake_case，例如 brand_abuse）：
是否新增业务类型：是/否
复用的现有分类（如果不新增）：

检测对象：域名/IP/URL/其他
支持的数据源：上传文件 / 新注册域名 / 手动输入
上传文件格式：csv / txt / xlsx
输入文件列名要求：
手动输入解析规则：
订阅是否支持：是/否
订阅默认数据源：通常是新注册域名
是否需要官方域名文件或参考文件：是/否；文件格式和列名：

模型文件路径（容器内相对 backend/app/models 的路径）：
模型文件是否允许入库：是/否；如果否，说明交付位置：
新增 Python 依赖：
新增环境变量：
是否调用外部网络/LLM：是/否；超时、重试、无 Key 降级策略：

算法入口函数期望：
输入参数：
返回值：
Excel 结果工作表：
statistics 字段：
逐条风险结果字段：

高风险判定规则：
默认预警策略（threshold=NULL 时）：
自定义阈值含义（0-100 如何映射到算法分数）：
风险等级枚举：
是否需要组织关联匹配：是/否；使用哪个字段作为域名：
通知附件希望展示的列：

前端页面需求：
任务列表展示名称：
订阅页展示名称和说明：
需要新增检测页面：是/否

最小验收样例：
样例输入文件或 5-10 条样例数据：
期望高风险结果：
期望 statistics：
失败样例和期望错误信息：
```

### 2. 准备算法材料

成员至少提供以下材料：

- 可运行的算法原型或说明文档。最好能给出一个纯 Python 函数，不依赖数据库、MinIO、FastAPI。
- 小样本输入文件和期望输出结果，用于 Codex 验证。
- 模型文件或模型文件下载/放置说明。大模型、训练数据、每日数据 zip、日志和临时产物不要直接提交。
- 依赖清单。新增后端依赖写明包名和版本范围，由 Codex 更新 `backend/requirements.txt`。
- 业务阈值说明。必须明确 `threshold=NULL` 的默认策略，以及前端 0-100 阈值如何转换为模型分数。

### 3. 约定算法适配器契约

推荐让 Codex 把算法包装成 `backend/app/models/<algorithm_key>_detection.py`，业务层只调用稳定函数。函数尽量无副作用，不直接写数据库、不直接写 MinIO。

推荐契约：

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

逐条风险记录建议至少包含：

```json
{
  "domain": "example.com",
  "risk_score": 0.91,
  "risk_level": "high",
  "is_high_risk": true,
  "reason": "命中原因"
}
```

如果不是域名算法，把 `domain` 替换为清晰的对象字段，例如 `ip` 或 `url`，并在接入卡中说明预警归档和通知如何展示。

## Codex 需要完成的代码事项

### 后端检测链路

Codex 需要根据接入类型检查并修改：

- `backend/app/models/<algorithm_key>_detection.py`：算法适配器。
- `backend/app/api/detection.py`：创建任务接口、参数校验、文件上传、`Task.extra`。
- `backend/app/services/task_dispatcher.py`：新增 Celery 投递函数。
- `backend/app/tasks/detection_tasks.py`：新增 Celery 任务入口。
- `backend/app/services/task_executor.py`：执行算法、上传结果、写任务状态和统计信息。
- `backend/app/entities/task.py`：如果新增 `task_type`，同步 SQLAlchemy 枚举。

一次性检测完成后，`tasks.extra` 至少应包含：

- `result_file_key`
- `result_bucket`
- `result_filename`
- `statistics`
- `completed_at`
- `progress`
- 订阅任务还要包含 `subscription_id` 和 `dateRange`

### 订阅和预警链路

Codex 需要根据接入类型检查并修改：

- `backend/app/api/subscription.py`
  - `_model_category_to_subscription_type()`
  - `_task_type_to_subscription_type()`
  - `create_subscription()`
  - `execute_subscription()`
  - 高风险结果提取逻辑
  - 预警附件生成逻辑
- `backend/app/services/actor_matcher/alert_file_mapping.py`：如果新增 `task_type`，同步允许列表。
- `backend/app/services/actor_matcher/alert_result_builder.py`：确保完整预警 JSON 能容纳新算法字段。
- `backend/app/services/notification/alert_notifier.py` 和 `backend/app/services/notification/*`：确保邮件/飞书文案和字段适配。

订阅默认只读取每日新注册域名数据：

```text
{DAILY_DATA_DIR}/{YYYY-MM}/{YYYY-MM-DD}-domain.zip
```

如果新算法订阅不适合用新注册域名，必须在接入卡里说明新的数据来源和调度策略。

### 数据库

如果新增业务类型，Codex 需要同步：

- `backend/db/init/01_schema.sql`
  - `models.model_category`
  - `training_tasks.model_category`
  - `tasks.task_type`
  - `alerts.task_type`
  - `alert_files.task_type`
- `backend/db/init/05_seed_core_data.sql`：新增官方模型种子数据和默认管理员绑定。
- `backend/db/migrations/<next>_add_<algorithm_key>_detection_task.sql`：给已有数据库使用的幂等迁移。
- `backend/app/entities/model.py`
- `backend/app/entities/task.py`
- `backend/app/entities/alert_file.py`
- `backend/app/api/subscription.py` 内定义的 `Alert.task_type` 枚举。

只改 `backend/db/init/*.sql` 不会影响已有 MySQL 数据卷，必须提供 migration。

### 前端

Codex 需要根据页面需求检查并修改：

- `frontend/src/router/dynamic-routes.ts`：新增检测页路由和菜单。
- `frontend/src/pages/detection/<algorithm-key>-detection/index.vue`：新增检测页面，或复用现有页面。
- `frontend/src/pages/detection/alert/index.vue`
  - `SubscriptionModelType`
  - 类型标签
  - 阈值说明
  - 订阅表和预警表展示
- `frontend/src/api`：如新增接口封装，URL 写相对 `/api` 的路径，不要写成 `/api/...` 后再被 `baseURL=/api` 叠加。

前端文案保持中文，UI 继续使用 Vue 3、Ant Design Vue、Pinia 和现有页面风格。

## 给 Codex 的提示词

### 全量接入提示词

把接入卡内容填好后，优先使用这个提示词：

```text
请在当前 APTHunter 仓库中把新算法「<算法中文名>」接入检测、订阅和预警流程。实际代码由你完成。

请先执行 git status，避免覆盖我已有改动。只改本次接入需要的文件。

算法接入卡如下：
<粘贴完整算法接入卡>

接入要求：
1. 先判断是否需要新增 model_category/task_type；如果能复用现有分类，请说明并复用。
2. 后端一次性检测要支持接入卡中声明的数据源，创建 Task 后通过 Celery 执行。
3. 订阅流程要在 execute_subscription() 中支持该算法，按接入卡的高风险规则创建 Alert。
4. 预警结果要归档到 MinIO + files + alert_files，并能被 /api/alerts 和 /api/alerts/{alert_id} 读取。
5. 通知附件和邮件/飞书摘要要能展示新算法的关键字段。
6. 如新增业务类型，同步 SQLAlchemy 枚举、init SQL、幂等 migration 和官方模型种子数据。
7. 如需要前端页面，同步路由、检测页、订阅页类型和阈值说明。
8. 不提交大模型、训练数据、日志或缓存产物。
9. 修改后按改动范围运行后端语法/导入检查和前端 pnpm typecheck；无法运行的验证说明原因。
```

### 只接一次性检测的提示词

```text
请只把「<算法中文名>/<algorithm_key>」接入一次性检测任务流程，暂时不接订阅预警。

算法材料：
<粘贴输入输出、模型路径、阈值、样例>

请完成：
1. 新增或整理 backend/app/models/<algorithm_key>_detection.py 适配器。
2. 在 backend/app/api/detection.py 增加创建任务接口和参数校验。
3. 在 task_dispatcher.py、detection_tasks.py、task_executor.py 增加 Celery 执行链路。
4. 结果保存到 results 桶，tasks.extra 写入 result_file_key/result_bucket/result_filename/statistics/completed_at/progress。
5. 如新增 task_type，同步 SQLAlchemy 枚举和数据库 migration。
6. 给出最小验证命令和结果。
```

### 接订阅和预警的提示词

```text
请在已有检测任务基础上，把「<算法中文名>/<algorithm_key>」接入订阅和预警流程。

高风险规则：
<粘贴默认策略、自定义阈值映射、逐条风险字段>

请完成：
1. 更新 backend/app/api/subscription.py 的模型类型映射、创建订阅、execute_subscription 和预警提取逻辑。
2. 订阅任务要写 Task，extra 包含 subscription_id、dateRange、statistics 和算法元数据。
3. 满足高风险规则时创建 Alert，并归档完整 JSON 到 MinIO + files + alert_files。
4. 更新 alert_file_mapping、alert_result_builder 和 notification 相关代码，使新字段可展示。
5. 更新前端订阅页的类型、标签、阈值说明和预警展示。
6. 补充或更新 migration，不能只改 init SQL。
7. 运行后端检查和前端 typecheck。
```

### 补前端页面的提示词

```text
请为「<算法中文名>/<algorithm_key>」补齐前端检测入口。

页面需求：
<粘贴数据源、表单字段、默认值、校验规则、结果展示需求>

请完成：
1. 在 frontend/src/pages/detection 下新增或复用页面。
2. 在 frontend/src/router/dynamic-routes.ts 增加菜单和路由。
3. 请求 URL 遵守项目约定：相对 /api 的路径，不要写成 /api/api。
4. 页面使用现有 Ant Design Vue 风格，文案为中文。
5. 同步任务列表或详情页中该 task_type 的中文名称和结果展示。
6. 运行 pnpm typecheck；如有 lint 改动再运行 pnpm lint。
```

### 验收和修复提示词

```text
请验证「<算法中文名>/<algorithm_key>」接入是否完整，并修复发现的问题。

请检查：
1. 数据库枚举、init SQL、migration、SQLAlchemy 枚举是否一致。
2. 一次性检测的 upload/newDomain/manualInput 是否按接入卡支持。
3. Celery 任务失败时是否把 Task 标为 failed 并写入 error。
4. 订阅执行是否能创建 Task、Alert、files、alert_files，并更新 next_run_at。
5. /api/alerts 和 /api/alerts/{alert_id} 是否能读取新算法预警结果。
6. 邮件/飞书通知是否包含关键字段且不会因通知失败阻塞订阅主流程。
7. 前端 typecheck 是否通过。

请给出具体验证命令、结果和仍未覆盖的风险。
```

## 验收清单

成员验收时至少确认：

- 新算法模型记录出现在模型列表或订阅模型列表中。
- 一次性检测能创建任务，任务状态从 `pending` 到 `processing` 到 `completed`。
- 结果文件能下载或查看，`statistics` 与样例预期一致。
- 订阅创建成功，`next_run_at` 合理。
- 手动触发 `/api/subscriptions/trigger` 后，订阅任务能产生检测任务。
- 满足高风险规则时，`alerts`、`files`、`alert_files` 都有记录。
- 预警列表和预警详情能展示高风险对象。
- 邮件/飞书无配置时不会无限重试；有配置时能发出通知。
- 前端 `pnpm typecheck` 通过。

## 常见问题

- **只新增前端类型但后端没接执行逻辑**：订阅页会显示模型，但调度后可能走错算法或无法产生预警。
- **只改 init SQL**：已有数据库不会自动重放初始化脚本，必须新增 migration。
- **新增 `task_type` 后忘记 `alert_file_mapping`**：预警归档会失败，导致任务可能变成 failed。
- **高风险规则不明确**：Codex 无法可靠实现预警筛选，必须先明确默认策略和自定义阈值含义。
- **算法函数直接操作数据库或 MinIO**：会让一次性检测和订阅链路难以复用，优先把副作用留在业务服务层。
- **外部 LLM 或网络调用无超时**：后台任务可能卡住；必须有超时、重试上限和无 Key 降级策略。
- **大模型直接提交**：不要提交大型模型、训练数据、每日数据 zip、日志或临时产物。
