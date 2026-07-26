# AGENTS.md

本文件是 APTHunter 仓库的 Agent 开发总规则。适用于整个项目根目录及其所有子目录，除非更深层目录另有 `AGENTS.md` 覆盖。

## 项目概览

- 项目是恶意域名检测系统：后端 `FastAPI + SQLAlchemy + Celery + MySQL + Redis + MinIO`，前端 `Vue 3 + Vite + TypeScript + Ant Design Vue + Pinia + UnoCSS`。
- Docker Compose 拓扑是 `frontend(Nginx) -> backend`，`backend/celery-worker -> mysql/redis/minio`。
- 主要目录：
  - `backend/app/api`：FastAPI 路由。
  - `backend/app/services`：任务调度、执行、通知、Actor 匹配等业务服务。
  - `backend/app/models`：检测模型与算法代码，不等同于数据库实体。
  - `backend/app/entities`：SQLAlchemy ORM 实体。
  - `backend/db/init`：首次初始化 SQL 和种子数据。
  - `backend/db/migrations`：后续数据库迁移 SQL。
  - `frontend/src/api`：前端接口封装。
  - `frontend/src/pages`：业务页面，检测相关页面集中在 `frontend/src/pages/detection`。
  - `frontend/src/utils/request.ts`：Axios 请求封装。

## 基本工作规则

- 开始改动前先看当前工作区状态，避免覆盖用户已有改动；不要回滚自己没有创建的修改。
- 优先使用 `rg`/`rg --files` 搜索代码和文件。
- 修改保持最小范围，遵循现有模块边界；不要顺手重构无关代码。
- 不提交或新增真实密钥、Token、生产密码、私有证书；`.env`、日志、缓存、构建产物不要入库。
- 删除文件、清理数据、重建数据卷、修改数据库结构前必须先确认影响范围；`docker compose down -v`、批量 `rm`、清空表等操作只能在明确要求下执行。
- 代码和文档默认使用中文业务术语；面向用户的提示、错误信息、页面文案保持中文。

## 启动与验证命令

优先根据改动范围选择最小验证。

### Docker Compose

```bash
docker compose up -d
docker compose ps
docker compose logs -f backend
docker compose logs -f celery-worker
```

- Compose 默认对外 Web 是 `http://localhost`。
- Compose 后端映射为 `127.0.0.1:8000:8000`。
- Compose MySQL 宿主机端口是 `127.0.0.1:3307`，容器内是 `mysql:3306`。
- Compose MinIO 宿主机端口是 `127.0.0.1:9000/9001`。

### 本地联调

```bash
./dev.sh
```

- `dev.sh` 会启动 FastAPI、Celery worker 和 Vite。
- 默认后端端口 `8001`，前端端口 `6678`。
- 本地后端默认连接 `127.0.0.1:3307` 的 MySQL 和 `127.0.0.1:6379` 的 Redis。
- Agent 为测试自行启动服务或监听端口时，测试完成后必须停止自己启动的进程并确认对应端口已释放。
- 如果端口或服务在 Agent 开始操作前已经由用户或其他进程启动，则不得擅自停止；只清理由 Agent 本轮启动的服务和端口。

### 后端

```bash
cd backend
source venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=. uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
PYTHONPATH=. celery -A celery_worker worker --loglevel=info
```

- 当前本地虚拟环境是 Python `3.10`。
- 后端入口是 `backend/app/main.py`，实际应用创建在 `backend/app/bootstrap/app_factory.py`。
- 数据库连接从 `MYSQL_URL` 读取；本地直接启动时 `backend/app/core/config.py` 会尝试读取根目录或后端目录的 `.env`。

### 前端

```bash
cd frontend
pnpm install
pnpm dev
pnpm build
pnpm typecheck
pnpm lint
```

- 使用 `pnpm`，不要引入 `npm`/`yarn` 锁文件。
- Node 要求 `>=20.15.0`，`packageManager` 是 `pnpm@10.17.1`。
- Vite 开发端口是 `6678`。

## 后端开发约束

- 新增 API 路由放在 `backend/app/api`，并在 `backend/app/bootstrap/app_factory.py` 中注册。
- 数据库实体放在 `backend/app/entities`，确保实体被应用启动路径导入，否则 `Base.metadata.create_all` 可能不会创建对应表。
- 复杂业务逻辑放在 `backend/app/services`，避免把大型流程堆在 API 路由函数里。
- 异步检测任务优先走 Celery：调度逻辑在 `task_dispatcher.py`，执行逻辑在 `task_executor.py` 和 `backend/app/tasks`。
- 数据库结构变更优先新增幂等 migration SQL 到 `backend/db/migrations`；只有兼容旧数据卷的极小 DDL 才考虑放入运行时兼容逻辑。
- SQL 使用参数绑定，不拼接用户输入。
- 返回给前端的接口结构要与现有页面兼容，改字段名或状态值时同步检查 `frontend/src/pages` 和 `frontend/src/api`。
- 依赖新增到 `backend/requirements.txt`；`requirements_all.txt` 只在确实需要全量依赖时同步维护。

## 模型和数据文件约束

- `backend/app/models/saved_model` 会被 Compose 挂载到容器 `/app/app/models/saved_model`，训练生成的 `.pkl` 会落到宿主机。
- 不要挂载或覆盖整个 `backend/app/models` 目录；`docker-compose.yml` 已注明只挂载 `saved_model`，否则会覆盖镜像内算法代码。
- `.gitignore` 已忽略 `backend/app/models/saved_model/*TRAIN*.pkl` 和 `backend/app/models/pretrained_model/`。
- 清理 `.pkl` 前必须查询数据库使用情况，至少检查：
  - `models.model_path` 和 `models.status`
  - `user_models.is_active`
  - `tasks.status in ('pending','processing')`
  - 需要时检查 `training_tasks.training_status`
- 恶意检测模型的 scaler 路径由模型文件名按代码规则将首个 `model` 替换为 `scaler` 得到，例如 `svm_model2.pkl -> svm_scaler2.pkl`。
- 官方恶意检测默认模型路径是 `saved_model/svm_model2.pkl`；DGA 默认模型是 `saved_model/dga_cnn_detector.keras`。
- 不要把大型模型、训练数据、每日数据 zip、日志或临时产物直接提交；`.zip` 受 Git LFS 规则管理。

## 数据库与对象存储

- MySQL 默认数据库是 `apthunter_new`；开发默认账号和端口以 `docker-compose.yml` 为准。
- MinIO 默认桶包括上传、结果、训练数据和预警结果等，具体访问通过 `backend/app/infra/minio_client.py` 和配置项完成。
- `backend/db/init/*.sql` 只会在新 MySQL 数据卷首次初始化时执行；已有数据卷不会自动重放这些 SQL。
- 对已有环境的修复请提供 migration 或幂等脚本，不要假设重建数据卷可接受。
- 数据清理脚本是 `backend/scripts/cleanup.py`；执行前必须确认目标环境和删除条件。

## 前端开发约束

- 请求封装在 `frontend/src/utils/request.ts`，默认 `baseURL` 是 `VITE_APP_BASE_API`，通常为 `/api`。
- 前端 API 文件里的 URL 应写成相对 `/api` 的路径，例如 `/user/info`；不要写成 `/api/user/info`，否则可能变成 `/api/api/...`。
- 开发环境 `VITE_ENABLE_H3_MOCK=false` 才会真实联调后端；不要在真实联调时打开 mock。
- 路径别名：
  - `~`、`@`、`~@` 指向 `frontend/src`
  - `~#` 指向 `frontend/src/enums`
- 页面优先使用现有 Ant Design Vue、Pinia、组合式 API 和项目组件风格；不要引入新的 UI 框架。
- 修改页面后至少运行 `pnpm typecheck`；涉及格式或 lint 规则时运行 `pnpm lint`。
- `frontend/types/auto-imports.d.ts` 等自动生成类型文件不要手工改，除非是为了解决生成配置本身。

## 接口与认证约定

- 前端 token 存储键是 `Authorization`，请求拦截器默认把 token 放入同名请求头。
- 后端接口若依赖登录态，应兼容现有 `Authorization`/`Bearer` 使用方式，改动时同步检查 `frontend/src/composables/authorization.ts` 和相关页面。
- 后端 401/403/500 会被前端请求拦截器统一弹通知；新增接口应返回清晰的 `msg` 或 FastAPI 错误信息。

## 通知与 LLM 相关约束

- 邮件、飞书、Anthropic、DeepSeek 等配置都来自环境变量；不要在代码中硬编码真实地址、密钥或个人账号。
- 触发外部 LLM 或网络请求的逻辑必须有超时、重试和日志；批处理要控制并发，参考现有 `PHISHING_LLM_*` 配置。
- 无 API Key 时应降级为明确错误或跳过可选能力，不要让后台任务无限重试。

## 旧归因模块状态

- 现有组织归因、组织关联和组织画像属于旧兼容实现，产品侧标记为**未在使用、待整体替换**。旧代码仍可能被历史检测或预警流程调用，因此不要直接删除或改变其兼容行为。
- 旧实现主要包括 `backend/app/services/actor_matcher/`、`backend/app/api/domain_matches.py`、`backend/app/api/dashboard_organization.py`、`frontend/src/pages/dashboard/profile/`，以及检测结果中现存的组织关联展示逻辑。
- 新功能不得把旧归因分数、组织画像缓存或旧匹配结果作为设计基础，也不要为其新增规则或字段。域名追踪只负责采集和保存可复用的基础设施与应用指纹，新的归因链路以后独立设计和接入。

## Git 与交付

- 本仓库可能长期存在未提交业务改动。Agent 只提交/描述自己本轮产生的变更。
- 二进制模型文件和大文件删除要在最终说明中列出依据和复查结果。
- 完成后说明做了什么、验证了什么、哪些验证因环境限制未执行。
- 不要把 `apthunter-app-images.tar`、`logs/`、`node_modules/`、`backend/venv/`、`.pnpm-store/`、`__pycache__/` 等产物纳入改动。
