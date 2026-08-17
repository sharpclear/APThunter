# Lazarus.day 采集容器

该目录是 APTHunter 仓库内可重复构建的 Lazarus.day 采集模块。采集器只访问公开来源、保存原始证据并通过内部 HTTP API 提供变更流，不直接连接 MySQL。

运行拓扑：

```text
lazarus-collector -> /api/v1/events -> celery-worker -> apt_event_candidates
```

运行数据保存在 Compose 命名卷 `lazarus_events` 和 `lazarus_logs` 中，不提交到 Git。组织和历史事件 CSV 在运行时由 APTHunter Compose 以只读方式挂载。

## 本地测试

```bash
cd collectors/lazarus_day
python -m pytest -q
```

## 构建

```bash
docker compose build lazarus-collector
```

若需要使用国内 Python 包镜像：

```bash
PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple docker compose build lazarus-collector
```

生产运行必须在项目根目录 `.env` 中配置至少 32 个字符的 `LAZARUS_DAY_API_KEY`。采集器仅在 Compose 内部网络暴露 8788，不映射宿主机端口。
