# Lazarus.day 事件采集模块

## 架构与边界

Lazarus.day 采集器作为 APTHunter Compose 中的独立服务运行。它只负责公开信息采集、标准化、证据保存和变更流 API，不连接 MySQL。APTHunter 的 Celery Worker 通过内部地址 `http://lazarus-collector:8788` 拉取变更，并完成最终校验、去重和入库。

数据流如下：

```text
Celery Beat（每周触发采集 / 每 10 分钟同步）
    -> Lazarus.day API 与采集 Worker
    -> apt_event_candidates 候选及审计记录
    -> 严格校验 + 事务去重
    -> apt_events 正式事件
    -> 现有仪表盘和事件接口直接展示
```

采集器的 8788 端口只通过 Compose `expose` 开放，不映射到虚拟机宿主机。采集产物、checkpoint 和 API SQLite 索引位于 `lazarus_events` 数据卷，日志位于 `lazarus_logs` 数据卷。容器限制为 0.5 CPU、768 MB 内存；实际采集仍使用串行请求和请求间隔。

## 自动导入规则

来源记录始终先写入 `apt_event_candidates`。只有同时满足以下条件的 variant 才进入 `apt_events`：

- 来源整体状态为 `accepted`，且 `review_required=false`；
- variant 的 `review_status=accepted`；
- 组织 ID 存在，组织名称精确匹配该 ID 的名称或别名；
- 日期精确到日或明确使用报告发布日期；
- 标题、描述、受控威胁类型、发布机构和 HTTP(S) 链接完整；
- `confidence >= 0.75`，且至少有一个 A/B 级主要证据，或两个 B/C 级证据；
- 未与现有事件的 `event_key`、规范化链接或“组织 + 日期 + 标题”重复。

未通过的记录保留为 `needs_review`，不会出现在正式事件展示中；重复记录标记为 `duplicate` 并关联已有事件。游标只和同一页候选/事件事务一起提交，因此导入失败不会跳过数据。

## Linux / 虚拟机部署

采集器源码已经纳入 APTHunter 仓库，Compose 直接从仓库内路径构建镜像：

```text
APTHunter/
└── collectors/
    └── lazarus_day/
```

虚拟机不再依赖同级的 `EventCapture/Lazarus.day` 目录，也不需要连接本机 Lazarus API。

先生成密钥：

```bash
openssl rand -hex 32
```

然后在 `APTHunter` 目录的 `.env` 中写入生成结果：

```bash
LAZARUS_DAY_API_KEY=粘贴上一步生成的64位十六进制字符串
LAZARUS_EVENT_SYNC_ENABLED=true
LAZARUS_EVENT_AUTO_IMPORT=false
```

推荐通过项目部署脚本构建、上传和升级；本地执行：

```bash
bash scripts/deploy-local.sh --build --tag "$DEPLOY_TAG" \
  --ssh-key ~/.ssh/apthunter_vm_ed25519
```

GitHub 代码同步到虚拟机后，在虚拟机执行：

```bash
bash scripts/deploy-remote.sh --tag "$DEPLOY_TAG"
```

后端启动时会自动执行 `019_add_lazarus_event_ingestion.sql`。新的 `lazarus_events` 卷初始为空，首次采集会从公开来源生成采集器自己的历史记录，随后 APTHunter 从变更流起点同步；现有事件会被识别为重复并建立映射，只有严格合格且不存在的事件才可能新增。原本机采集目录里的运行数据不会被打进镜像，如需保留它们应单独迁移数据，而不是提交到 Git。

验证：

```bash
docker compose ps
docker compose exec lazarus-collector python -c 'import os, urllib.request; r=urllib.request.Request("http://127.0.0.1:8788/readyz", headers={"X-API-Key": os.environ["LAZARUS_DAY_API_KEY"]}); print(urllib.request.urlopen(r).read().decode())'
docker compose logs --tail=100 lazarus-collector celery-worker celery-beat
```

登录 APTHunter 后可调用以下运维接口：

- `GET /api/event-ingestion/lazarus/status`：游标、最近同步批次和候选计数；
- `GET /api/event-ingestion/lazarus/candidates?decision=needs_review`：查看待审核候选；
- `POST /api/event-ingestion/lazarus/trigger`：立即触发增量采集；
- `POST /api/event-ingestion/lazarus/sync`：立即同步已经采集的变更。

确认新链路连续成功运行后，应停用原 Windows Lazarus 计划任务，避免两套调度器同时采集。旧采集目录可以暂时保留作审计和必要的数据迁移来源。

## 开关与回滚

把 `LAZARUS_EVENT_AUTO_IMPORT=false` 后重建 backend、worker 和 beat，所有新记录仍会同步到候选表，但不会写入正式事件表。把 `LAZARUS_EVENT_SYNC_ENABLED=false` 后重建 celery-beat 可停止周期触发；手工 API 仍然可用。

迁移新增的正式事件可通过 `apt_event_candidates.apt_event_id` 追溯到来源记录。不要直接删除候选、游标或采集数据卷，否则会丢失审计映射，或导致历史变更重新回放。
