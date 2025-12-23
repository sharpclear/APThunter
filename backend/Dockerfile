# 多阶段构建 Dockerfile for FastAPI Backend
# 第一阶段：构建阶段（可选，用于安装依赖）
FROM python:3.10-slim AS builder

# 设置工作目录
WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements.txt .

# 安装 Python 依赖到临时目录
RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple/ --no-cache-dir --user -r requirements.txt

# 第二阶段：运行阶段
FROM python:3.10-slim

# 设置工作目录
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

# 复制应用代码
COPY app/ ./app/

# 设置 Python 环境变量
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# 暴露端口（FastAPI 默认端口，可通过环境变量覆盖）
EXPOSE 8000

# 健康检查（检查 FastAPI 文档页面是否可访问）
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/docs || exit 1

# 启动命令（使用 uvicorn 运行 FastAPI 应用）
# 可以通过环境变量覆盖 host 和 port
# 如果需要 GPU 支持，请使用 nvidia/cuda 基础镜像，例如：
# FROM nvidia/cuda:12.1.0-runtime-ubuntu22.04
# 并安装 Python 3.10
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# 环境变量说明（可在运行时通过 -e 或 docker-compose.yml 设置）：
# - MINIO_ENDPOINT: MinIO 服务地址（默认: localhost:9000）
# - MINIO_ACCESS_KEY: MinIO 访问密钥（默认: minioadmin）
# - MINIO_SECRET_KEY: MinIO 密钥（默认: 123456789）
# - MINIO_BUCKET: MinIO 存储桶名称（默认: uploads）
# - MYSQL_URL: MySQL 数据库连接字符串
# - IMPERSONATION_MODEL_NAME: 仿冒检测模型名称（默认: impersonation_detector）

