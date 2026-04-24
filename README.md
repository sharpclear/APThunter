# ATDV Pro - 恶意域名检测系统

## 项目简介

基于 FastAPI + Vue3 的恶意域名检测系统，支持恶意性检测和仿冒域名检测功能。项目采用 Docker Compose 一键部署，包含完整的前后端服务、数据库和对象存储。

## 系统要求

- **Docker**: >= 20.10
- **Docker Compose**: >= 2.0
- **内存**: 至少 4GB 可用内存（推荐 8GB+）
- **磁盘空间**: 至少 10GB 可用空间
- **操作系统**: Linux / macOS / Windows (WSL2)

## 快速开始

### 1. 克隆项目

```bash
git clone <your-repo-url>
cd atdv-pro
```

### 2. 一键启动所有服务

```bash
docker-compose up -d
```

### 3. 等待服务启动

首次启动需要下载镜像和构建，可能需要 5-10 分钟。查看启动日志：

```bash
# 查看所有服务日志
docker-compose logs -f

# 查看特定服务日志
docker-compose logs -f backend
docker-compose logs -f frontend
```

### 4. 验证服务状态

```bash
docker-compose ps
```

所有服务状态应为 `Up` 或 `Up (healthy)`。

### 5. 访问应用

- **前端应用**: http://localhost
- **后端 API 文档**: http://localhost:8000/docs
- **后端 API**: http://localhost:8000/api
- **MinIO 控制台**: http://localhost:9001
  - 用户名: `minioadmin`
  - 密码: `123456789`

## 服务说明

| 服务 | 端口 | 说明 |
|------|------|------|
| Frontend | 80 | Vue3 + Ant Design Vue 前端应用 |
| Backend | 8000 | FastAPI 后端服务 |
| MySQL | 3306 | 数据库服务 |
| MinIO API | 9000 | 对象存储 API |
| MinIO Console | 9001 | MinIO 管理控制台 |

## 常用命令

### 启动和停止

```bash
# 启动所有服务（后台运行）
docker-compose up -d

# 启动并查看日志
docker-compose up

# 停止所有服务
docker-compose down

# 停止并删除数据卷（⚠️ 会删除所有数据）
docker-compose down -v
```

### 查看状态和日志

```bash
# 查看服务状态
docker-compose ps

# 查看所有服务日志
docker-compose logs -f

# 查看特定服务日志
docker-compose logs -f [service_name]

# 查看最近 100 行日志
docker-compose logs --tail=100 [service_name]
```

### 重启服务

```bash
# 重启所有服务
docker-compose restart

# 重启特定服务
docker-compose restart [service_name]
```

### 重建服务

```bash
# 重新构建并启动服务
docker-compose up -d --build

# 仅重新构建特定服务
docker-compose build [service_name]
```

## 配置说明

### 修改数据库配置

编辑 `docker-compose.yml` 中的 MySQL 服务配置：

```yaml
mysql:
  environment:
    MYSQL_ROOT_PASSWORD: your_root_password
    MYSQL_DATABASE: your_database_name
    MYSQL_USER: your_username
    MYSQL_PASSWORD: your_password
```

同时需要更新 `backend` 服务中的 `MYSQL_URL` 环境变量。

### 修改 MinIO 配置

编辑 `docker-compose.yml` 中的 MinIO 服务配置：

```yaml
minio:
  environment:
    MINIO_ROOT_USER: your_access_key
    MINIO_ROOT_PASSWORD: your_secret_key
```

同时需要更新 `backend` 服务中的 MinIO 相关环境变量。

### 修改端口映射

如果端口冲突，可以修改 `docker-compose.yml` 中的端口映射：

```yaml
services:
  frontend:
    ports:
      - "8080:80"  # 将前端改为 8080 端口
  backend:
    ports:
      - "8001:8000"  # 将后端改为 8001 端口
```

### 环境变量说明

后端服务支持以下环境变量：

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `MINIO_ENDPOINT` | MinIO 服务地址 | `minio:9000` |
| `MINIO_ACCESS_KEY` | MinIO 访问密钥 | `minioadmin` |
| `MINIO_SECRET_KEY` | MinIO 密钥 | `123456789` |
| `MINIO_BUCKET` | MinIO 存储桶名称 | `uploads` |
| `MYSQL_URL` | MySQL 数据库连接字符串 | 见 docker-compose.yml |
| `IMPERSONATION_MODEL_NAME` | 仿冒检测模型名称 | `impersonation_detector` |

## 故障排查

### 服务无法启动

1. **检查端口占用**
   ```bash
   # Linux/macOS
   lsof -i :80
   lsof -i :8000
   lsof -i :3306
   
   # Windows
   netstat -ano | findstr :80
   ```

2. **检查磁盘空间**
   ```bash
   df -h
   ```

3. **查看详细错误日志**
   ```bash
   docker-compose logs [service_name]
   ```

### 前端无法访问后端 API

1. **检查后端服务是否正常运行**
   ```bash
   curl http://localhost:8000/docs
   ```

2. **检查 nginx 配置**
   ```bash
   docker-compose exec frontend nginx -t
   ```

3. **检查网络连接**
   ```bash
   docker-compose exec frontend ping backend
   ```

### 数据库连接失败

1. **等待 MySQL 完全启动**
   - 首次启动 MySQL 需要初始化，可能需要 1-2 分钟
   - 检查健康状态: `docker-compose ps mysql`

2. **检查数据库日志**
   ```bash
   docker-compose logs mysql
   ```

3. **手动连接测试**
   ```bash
   docker-compose exec mysql mysql -u apthunter -p4CyUhr2zu6! apthunter_new
   ```

### 构建失败

1. **清理 Docker 缓存**
   ```bash
   docker system prune -a
   ```

2. **重新构建**
   ```bash
   docker-compose build --no-cache
   ```

### MinIO 无法访问

1. **检查 MinIO 服务状态**
   ```bash
   docker-compose ps minio
   ```

2. **检查 MinIO 日志**
   ```bash
   docker-compose logs minio
   ```

3. **访问控制台**
   - 浏览器访问: http://localhost:9001
   - 使用默认账号登录

## 数据持久化

项目使用 Docker volumes 持久化数据：

- `mysql_data`: MySQL 数据库数据
- `minio_data`: MinIO 对象存储数据
- `backend_data`: 后端应用数据

数据存储在 Docker 管理的 volumes 中，即使删除容器也不会丢失数据。

## 开发模式

### 前端开发

如果需要修改前端代码并实时查看效果：

1. 停止前端容器
   ```bash
   docker-compose stop frontend
   ```

2. 在本地启动前端开发服务器
   ```bash
   cd frontend
   pnpm install
   pnpm dev
   ```

3. 修改 `frontend/src/pages/detection/malicious-detection/index.vue` 中的 `API_BASE` 为 `http://localhost:8000`

### 后端开发

如果需要修改后端代码：

1. 停止后端容器
   ```bash
   docker-compose stop backend
   ```

2. 在本地启动后端服务
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

## 项目结构

```
atdv-pro/
├── backend/              # 后端服务
│   ├── app/             # 应用代码
│   ├── Dockerfile       # 后端 Docker 配置
│   └── requirements.txt  # Python 依赖
├── frontend/            # 前端服务
│   ├── src/             # 源代码
│   ├── Dockerfile       # 前端 Docker 配置
│   └── default.conf     # Nginx 配置
├── nginx/               # Nginx 配置
│   └── nginx.conf       # Nginx 主配置
├── docker-compose.yml   # Docker Compose 配置
└── README.md            # 项目说明文档
```

## 安全建议

⚠️ **生产环境部署前请务必修改以下配置：**

1. **修改所有默认密码**
   - MySQL root 密码
   - MySQL 用户密码
   - MinIO 访问密钥

2. **使用环境变量文件**
   - 创建 `.env` 文件存储敏感信息
   - 不要将 `.env` 文件提交到版本控制

3. **配置防火墙**
   - 仅开放必要的端口
   - 限制数据库和 MinIO 的访问

4. **启用 HTTPS**
   - 配置 SSL 证书
   - 修改 nginx 配置支持 HTTPS

## 技术支持

如有问题，请：

1. 查看本文档的故障排查部分
2. 检查服务日志: `docker-compose logs`
3. 提交 Issue 或联系项目维护者

## 许可证

[添加您的许可证信息]

## 更新日志

### v1.0.0
- 初始版本
- 支持恶意性检测和仿冒域名检测
- Docker Compose 一键部署

