# Lazarus.day 采集容器

该目录是 APTHunter 仓库内可重复构建的 Lazarus.day 采集模块。采集器只访问公开来源、保存原始证据并通过内部 HTTP API 提供变更流，不直接连接 MySQL。

运行拓扑：

```text
lazarus.day -> lazarus-collector
                         | -> Windows Qianxin API -> shared Qwen3-4B
                         v
                  /api/v1/events -> celery-worker -> apt_events
```

来源抓取、checkpoint 和组织精确匹配仍全部在虚拟机容器中执行；Windows 只提供
已有模型的结构化补全，不承担 Lazarus 定时调度。容器会对模型返回的来源哈希、
逐字引文、Actor 名称、受控威胁类型和中文展示文案再次校验。

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

生产运行必须在项目根目录 `.env` 中配置至少 32 个字符的
`LAZARUS_DAY_API_KEY`。模型补全复用现有奇安信配置，也可单独覆盖：

```dotenv
QIANXIN_API_URL=http://<Windows内网IP>:8787
QIANXIN_API_KEY=<奇安信 API 密钥>
# 可选覆盖：
# LAZARUS_ENRICHMENT_API_URL=http://<Windows内网IP>:8787
# LAZARUS_ENRICHMENT_API_KEY=<专用密钥>
LAZARUS_ENRICHMENT_TIMEOUT=900
```

模型不可达时采集不会丢失：原始结果进入待补全队列，后续批次重试。采集器仅在
Compose 内部网络暴露 8788，不映射宿主机端口；Windows 8787 应由防火墙限制为
虚拟机来源。
