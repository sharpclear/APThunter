# 环境变量配置说明

本文档说明项目中使用的环境变量及其配置方法。

## Docker Compose 环境变量

### MySQL 服务

| 变量名 | 说明 | 默认值 | 必需 |
|--------|------|--------|------|
| `MYSQL_ROOT_PASSWORD` | MySQL root 用户密码 | `rootpassword123` | 是 |
| `MYSQL_DATABASE` | 初始创建的数据库名 | `apthunter_new` | 否 |
| `MYSQL_USER` | 应用数据库用户 | `apthunter` | 否 |
| `MYSQL_PASSWORD` | 应用数据库用户密码 | `4CyUhr2zu6!` | 否 |

### MinIO 服务

| 变量名 | 说明 | 默认值 | 必需 |
|--------|------|--------|------|
| `MINIO_ROOT_USER` | MinIO 管理员用户名 | `minioadmin` | 是 |
| `MINIO_ROOT_PASSWORD` | MinIO 管理员密码 | `123456789` | 是 |

### 后端服务

| 变量名 | 说明 | 默认值 | 必需 |
|--------|------|--------|------|
| `MINIO_ENDPOINT` | MinIO 服务地址（容器内） | `minio:9000` | 是 |
| `MINIO_ACCESS_KEY` | MinIO 访问密钥 | `minioadmin` | 是 |
| `MINIO_SECRET_KEY` | MinIO 密钥 | `123456789` | 是 |
| `MINIO_BUCKET` | MinIO 存储桶名称 | `uploads` | 是 |
| `MYSQL_URL` | MySQL 连接字符串 | `mysql+pymysql://apthunter:4CyUhr2zu6!@mysql:3306/apthunter_new` | 是 |
| `IMPERSONATION_MODEL_NAME` | 仿冒检测模型名称 | `impersonation_detector` | 否 |

### 前端服务

| 变量名 | 说明 | 默认值 | 必需 |
|--------|------|--------|------|
| `API_BASE_URL` | 后端 API 地址（容器内） | `http://backend:8000` | 否 |

## 配置方式

### 方式一：直接修改 docker-compose.yml

编辑 `docker-compose.yml` 文件，在对应服务的 `environment` 部分修改环境变量：

```yaml
services:
  backend:
    environment:
      MINIO_ENDPOINT: minio:9000
      MINIO_ACCESS_KEY: your_access_key
      # ... 其他变量
```

### 方式二：使用 .env 文件（推荐）

1. 在项目根目录创建 `.env` 文件：

```bash
# MySQL 配置
MYSQL_ROOT_PASSWORD=your_secure_password
MYSQL_DATABASE=apthunter_new
MYSQL_USER=apthunter
MYSQL_PASSWORD=your_secure_password

# MinIO 配置
MINIO_ROOT_USER=your_minio_user
MINIO_ROOT_PASSWORD=your_minio_password

# 后端配置
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=your_minio_user
MINIO_SECRET_KEY=your_minio_password
MINIO_BUCKET=uploads
MYSQL_URL=mysql+pymysql://apthunter:your_secure_password@mysql:3306/apthunter_new
IMPERSONATION_MODEL_NAME=impersonation_detector
```

2. 在 `docker-compose.yml` 中使用变量：

```yaml
services:
  mysql:
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
      MYSQL_DATABASE: ${MYSQL_DATABASE}
      # ...
```

3. 启动服务：

```bash
docker-compose up -d
```

⚠️ **注意**: `.env` 文件包含敏感信息，不要提交到版本控制系统！

## 生产环境配置建议

### 1. 使用强密码

- MySQL root 密码：至少 16 位，包含大小写字母、数字和特殊字符
- MinIO 密码：至少 16 位，包含大小写字母、数字和特殊字符

### 2. 使用环境变量管理工具

- Docker Secrets（Docker Swarm）
- Kubernetes Secrets
- HashiCorp Vault
- AWS Secrets Manager

### 3. 限制访问

- 使用防火墙限制数据库和 MinIO 的访问
- 仅允许必要的 IP 地址访问管理端口

### 4. 定期轮换密码

- 定期更换数据库密码
- 定期更换 MinIO 访问密钥

## 环境变量验证

启动服务后，可以验证环境变量是否正确设置：

```bash
# 检查后端环境变量
docker-compose exec backend env | grep MINIO
docker-compose exec backend env | grep MYSQL

# 检查 MySQL 配置
docker-compose exec mysql env | grep MYSQL

# 检查 MinIO 配置
docker-compose exec minio env | grep MINIO
```

## 故障排查

### 环境变量未生效

1. 检查 `.env` 文件是否存在且格式正确
2. 确认 `docker-compose.yml` 中正确引用了变量
3. 重启服务: `docker-compose restart [service_name]`

### 连接失败

1. 检查环境变量中的服务地址是否正确
2. 确认容器网络连接正常
3. 查看服务日志: `docker-compose logs [service_name]`

