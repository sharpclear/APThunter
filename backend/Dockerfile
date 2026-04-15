# 多阶段构建 Dockerfile for FastAPI Backend
# 第一阶段：构建阶段（可选，用于安装依赖）
FROM python:3.10-slim AS builder

# 设置工作目录
WORKDIR /app

# 配置 Debian 使用国内镜像源（加速下载，减少构建时间）
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
    sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list 2>/dev/null || \
    (echo "deb https://mirrors.aliyun.com/debian/ bookworm main" > /etc/apt/sources.list && \
     echo "deb https://mirrors.aliyun.com/debian-security/ bookworm-security main" >> /etc/apt/sources.list && \
     echo "deb https://mirrors.aliyun.com/debian/ bookworm-updates main" >> /etc/apt/sources.list)

# 安装系统依赖（分步安装，减少单次内存占用）
# 先更新包列表
RUN apt-get update

# 单独安装 gcc（减少内存峰值）
RUN apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

# 再次更新并安装 g++
RUN apt-get update && \
    apt-get install -y --no-install-recommends g++ && \
    rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements.txt .

# 安装 Python 依赖到临时目录（增加超时时间）
# 配置 pip 使用国内镜像源（解决依赖包下载超时问题）
RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple && \
    pip config set global.trusted-host pypi.tuna.tsinghua.edu.cn

# 先安装 CPU 版本的 PyTorch（使用 PyTorch 官方源，但依赖从国内镜像下载）
RUN pip install --default-timeout=1000 \
    --user \
    torch>=2.7.1 \
    --extra-index-url https://download.pytorch.org/whl/cpu

# 安装其他依赖
RUN pip install --default-timeout=1000 \
    --user \
    -i https://pypi.tuna.tsinghua.edu.cn/simple/ \
    -r requirements.txt

# 第二阶段：运行阶段
FROM python:3.10-slim

# 配置 Debian 使用国内镜像源
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
    sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list 2>/dev/null || \
    (echo "deb https://mirrors.aliyun.com/debian/ bookworm main" > /etc/apt/sources.list && \
     echo "deb https://mirrors.aliyun.com/debian-security/ bookworm-security main" >> /etc/apt/sources.list && \
     echo "deb https://mirrors.aliyun.com/debian/ bookworm-updates main" >> /etc/apt/sources.list)

# 设置工作目录（先设置为 /app，用于复制文件）
WORKDIR /app

# 安装运行时系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 从构建阶段复制已安装的 Python 包
COPY --from=builder /root/.local /root/.local

# 确保使用本地安装的包
ENV PATH=/root/.local/bin:$PATH

# 复制应用代码与定时任务脚本（cron / docker exec 可用 /app/scripts/...）
COPY app/ ./app/
COPY scripts/ ./scripts/

# 切换到应用目录（关键修改：与本地运行方式一致）
WORKDIR /app/app

# 设置 Python 环境变量（PYTHONPATH 使包名 app 映射到 /app/app，供 uvicorn 与 celery 一致解析）
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

# 暴露端口（FastAPI 默认端口，可通过环境变量覆盖）
EXPOSE 8000

# 健康检查（检查 FastAPI 文档页面是否可访问）
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/docs || exit 1

# 启动命令（关键修改：使用 main:app 而不是 app.main:app）
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

# 环境变量说明（可在运行时通过 -e 或 docker-compose.yml 设置）：
# - MINIO_ENDPOINT: MinIO 服务地址（默认: localhost:9000）
# - MINIO_ACCESS_KEY: MinIO 访问密钥（默认: minioadmin）
# - MINIO_SECRET_KEY: MinIO 密钥（默认: 123456789）
# - MINIO_BUCKET: MinIO 存储桶名称（默认: uploads）
# - MYSQL_URL: MySQL 数据库连接字符串
# - IMPERSONATION_MODEL_NAME: 仿冒检测模型名称（默认: impersonation_detector）
# - REDIS_URL / CELERY_BROKER_URL / CELERY_RESULT_BACKEND: Celery（Compose 中建议使用 redis://redis:6379/0）
# - SMTP_*: 预警邮件（app/services/notification/email_service.py）
# - ALERT_EMAIL_ENABLED / FEISHU_ENABLE_PUSH / FEISHU_WEBHOOK_URL / FEISHU_BOT_SECRET / APP_PUBLIC_BASE_URL / FEISHU_HTTP_*: 预警飞书（app/core/config.py，由 docker-compose 注入）

