# APT 历史图谱目录

本目录保存随项目分发的默认 APT 历史图谱。未设置
`APT_ATTRIBUTION_GRAPH_DIR` 时，后端直接从本目录加载图谱。目录至少需要：

- `graph_nodes.csv`
- `graph_edges.csv`

可选文件：

- `apt_profiles.json`
- `historical_ioc_graph_summary.json`

候选域名和实时补全结果不会写入这里。更新图谱时由管理员停止相关归因任务，
人工替换 CSV 后再启动任务；服务会根据文件修改时间自动重新加载。

Docker Compose 默认把宿主机本目录只读挂载到后端和 Celery worker，无需配置
项目外部路径。如确需临时切换其他图谱，也可以在根目录 `.env` 中设置
`APT_ATTRIBUTION_GRAPH_HOST_DIR=/path/to/historical_graph`，把其他宿主机目录
只读挂载到容器内；应用代码只读取容器内的 `APT_ATTRIBUTION_GRAPH_DIR`。
