# 后端脚本说明

## 域名数据幂等导入

`import_domains.py` 用于把 `backend/db/init/domains.csv` 导入已有的 `domains` 表，适合本机和虚拟机中已经存在 MySQL 数据卷的环境。

### 导入规则

- 以规范化后的 `domain_name` 作为唯一匹配条件，不使用 CSV 中的 `id`，避免与已有数据库主键冲突。
- 同一个域名在 CSV 中重复出现时保留第一次出现的记录，与首次初始化 SQL 的处理方式一致。
- 已存在的数据不会被降级为良性；默认仅在原组织为空时补充 `organization_id`。
- 使用事务和批量写入，执行失败时会回滚；可重复执行，不会重复插入域名。
- 域名导入不会自动查询或生成 WHOIS、DNS、SSL 证书信息。

### 虚拟机 Docker Compose 导入

先确保虚拟机使用的后端镜像包含最新的 `scripts/import_domains.py` 和 `db/init/domains.csv`。如果在虚拟机上从源码构建，可执行：

```bash
docker compose build backend mysql
```

先执行预检查，不写入数据库：

```bash
docker compose run --rm -T --no-deps backend \
  python /app/scripts/import_domains.py \
  --file /app/db/init/domains.csv \
  --dry-run
```

确认预检查结果后正式导入：

```bash
docker compose run --rm -T --no-deps backend \
  python /app/scripts/import_domains.py \
  --file /app/db/init/domains.csv
```

脚本默认从容器的 `MYSQL_URL` 环境变量读取数据库连接。正式导入前不需要停止其他容器，也不要删除或重建 MySQL 数据卷。

### 新部署与已有部署

- 全新部署且使用空 MySQL 数据卷时，MySQL 初始化流程会自动读取更新后的 `backend/db/init/domains.csv`。
- 已有部署的数据卷不会重新执行 `backend/db/init` 下的初始化 SQL，必须运行上述幂等导入脚本。
- 如果需要强制让 CSV 中的组织归属覆盖数据库现有归属，可显式添加 `--sync-organization`；常规增量导入不建议使用。

## 数据清理脚本

## 概述

`cleanup.py` 是一个定期清理数据库、文件系统和MinIO中孤立数据的脚本。使用APScheduler实现每30天自动执行一次。

## 清理规则

### 1. 文件系统中的pkl文件清理
- **删除条件**：
  - `model_type='custom'` 的模型
  - `user_models` 表中没有任何记录
  - `tasks` 表中没有使用记录
- **删除内容**：
  - 模型pkl文件（如 `model_xxx.pkl`）
  - 标准化器pkl文件（如 `scaler_xxx.pkl`）
  - `training_tasks` 表中的训练记录
  - MinIO `traindata` 桶中关联的训练数据文件

### 2. MinIO清理

#### uploads桶
- **删除条件**：桶中存在但 `files` 表中没有记录的文件

#### results桶
- **删除条件**：桶中存在但 `tasks` 表的 `extra` 字段中 `result_file_key` 都没有的文件

#### traindata桶
- **删除条件**：与已删除模型关联的训练数据文件（在文件系统清理时同步删除）

### 3. 数据库清理
- **删除条件**：
  - `model_type='custom'` 的模型
  - `user_models` 表中没有任何记录
  - `tasks` 表中没有使用记录
- **注意**：此清理主要作为补充，因为文件系统清理已经删除了大部分符合条件的模型记录

## 使用方法

### 安装依赖

```bash
pip install APScheduler>=3.10.0
```

或使用项目的requirements.txt：

```bash
pip install -r requirements.txt
```

### 运行方式

#### 1. 定时运行（推荐）

脚本会每30天自动执行一次，并立即执行一次：

```bash
python backend/scripts/cleanup.py
```

#### 2. 单次运行

如果只想立即执行一次清理任务（不启动定时任务）：

```bash
python backend/scripts/cleanup.py --run-once
```

### 环境变量配置

脚本使用以下环境变量（与主应用一致）：

- `MINIO_ENDPOINT`: MinIO服务地址（默认：`localhost:9000`）
- `MINIO_ACCESS_KEY`: MinIO访问密钥（默认：`minioadmin`）
- `MINIO_SECRET_KEY`: MinIO密钥（默认：`123456789`）
- `MYSQL_URL`: MySQL数据库连接URL（默认：`mysql+pymysql://apthunter:4CyUhr2zu6!@localhost:3306/apthunter_new`）

### 日志

脚本会生成日志文件 `cleanup.log`，同时也会输出到控制台。

日志包含：
- 清理过程的详细信息
- 删除的文件和记录统计
- 错误信息（如果有）

## 注意事项

1. **数据安全**：
   - 脚本会永久删除文件和数据库记录，请确保已备份重要数据
   - 建议在测试环境先运行 `--run-once` 模式验证

2. **执行时机**：
   - 定时任务会在启动时立即执行一次，然后每30天执行一次
   - 建议在系统维护时间窗口运行

3. **权限要求**：
   - 需要数据库读写权限
   - 需要MinIO的读写权限
   - 需要文件系统的写权限（删除pkl文件）

4. **性能考虑**：
   - 清理过程可能需要一些时间，特别是MinIO桶中有大量文件时
   - 建议在系统负载较低时运行

## 集成到系统

### 作为独立服务运行

可以创建一个systemd服务或使用supervisor来管理这个脚本：

```ini
[program:cleanup]
command=/path/to/python /path/to/backend/scripts/cleanup.py
directory=/path/to/backend
autostart=true
autorestart=true
user=your_user
```

### 作为Docker容器运行

可以在Dockerfile中添加：

```dockerfile
CMD ["python", "scripts/cleanup.py"]
```

或在docker-compose.yml中：

```yaml
services:
  cleanup:
    build: .
    command: python scripts/cleanup.py
    environment:
      - MINIO_ENDPOINT=${MINIO_ENDPOINT}
      - MINIO_ACCESS_KEY=${MINIO_ACCESS_KEY}
      - MINIO_SECRET_KEY=${MINIO_SECRET_KEY}
      - MYSQL_URL=${MYSQL_URL}
```

## APT 组织与事件参考数据导入

`import_apt_reference.py` 从 `backend/db/init/apt_organizations.csv` 和
`backend/db/init/apt_events.csv` 读取参考数据，通过记录 ID 幂等更新组织和事件，并重新统计各组织的事件数量。
导入在一个数据库事务内完成，不会清空事件表、组织表或其他业务数据。

更新后端镜像并执行数据库迁移：

```bash
docker compose build backend
docker compose up -d --no-deps backend
docker compose exec -T backend python /app/scripts/db_bootstrap.py --skip-init --skip-seed
```

先预演并核对新增、更新数量：

```bash
docker compose exec -T backend python /app/scripts/import_apt_reference.py --dry-run
```

确认后执行正式导入；同一批数据可安全重复执行：

```bash
docker compose exec -T backend python /app/scripts/import_apt_reference.py
```
