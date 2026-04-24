# 数据清理脚本

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
