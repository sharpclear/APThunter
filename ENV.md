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
| `IMPERSONATION_FULL_WHITELIST_PATH` | 仿冒检测系统全量官方白名单路径；订阅未上传官方域名文件时使用 | `/app/app/data/official_domains/full_whitelist.csv` | 否 |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | 登录 JWT 有效期（分钟） | `1440`（24 小时） | 否 |
| `DEEPSEEK_API_KEY` | DeepSeek API Key，用于官方域名解析和仿冒域名 LLM 研判 | 空 | 是（使用事件名/单位名创建仿冒检测时） |
| `DEEPSEEK_MODEL` | DeepSeek 模型名称 | `deepseek-v4-flash` | 否 |
| `DEEPSEEK_API_URL` | DeepSeek Chat Completions API 地址 | `https://api.deepseek.com/chat/completions` | 否 |
| `OFFICIAL_DOMAIN_RESOLVER_MAX_DOMAINS` | 事件名/单位名最多解析的官方域名数 | `20` | 否 |
| `IMPERSONATION_LLM_MAX_RETRIES` | 仿冒域名 LLM 调用最大重试次数 | `3` | 否 |

### Lazarus.day 事件采集

| 变量名 | 说明 | 默认值 | 必需 |
|--------|------|--------|------|
| `LAZARUS_DAY_API_KEY` | APTHunter 与采集器之间的内部 API 密钥 | 无 | 是 |
| `LAZARUS_EVENT_SYNC_ENABLED` | 启用 Celery Beat 周期采集和同步 | `true`（Compose） | 否 |
| `LAZARUS_EVENT_AUTO_IMPORT` | 严格校验通过后写入正式事件表；关闭时仅写候选表 | `false` | 否 |
| `LAZARUS_EVENT_SYNC_INTERVAL_SEC` | 拉取采集器变更流的间隔（秒，最小 60） | `600` | 否 |
| `LAZARUS_EVENT_PAGE_LIMIT` | 单页变更数（1～200） | `100` | 否 |
| `LAZARUS_EVENT_MAX_PAGES_PER_SYNC` | 单次任务最多同步页数 | `20` | 否 |
| `LAZARUS_EVENT_HTTP_TIMEOUT_SEC` | 内部 API 请求超时（秒） | `30` | 否 |

### Qianxin 事件采集

| 变量名 | 说明 | 默认值 | 必需 |
|--------|------|--------|------|
| `QIANXIN_API_URL` | 虚拟机可访问的 Windows Qianxin API 地址 | 空 | 是（启用同步时） |
| `QIANXIN_API_KEY` | 与 Windows 用户级 `QIANXIN_API_KEY` 相同的密钥 | 空 | 是（启用同步时） |
| `QIANXIN_EVENT_SYNC_ENABLED` | 启用 Celery Beat 周期拉取事件候选 | `false` | 否 |
| `QIANXIN_COLLECTION_TRIGGER_ENABLED` | 由 APTHunter 每周触发 Qianxin 采集；Windows 计划任务仍启用时应保持关闭 | `false` | 否 |
| `QIANXIN_EVENT_AUTO_IMPORT` | 严格校验通过后写入正式事件表；首次接入应保持关闭 | `false` | 否 |
| `QIANXIN_EVENT_SYNC_INTERVAL_SEC` | 拉取事件变更流的间隔（秒，最小60） | `600` | 否 |
| `QIANXIN_EVENT_PAGE_LIMIT` | 单页变更数（1～200） | `100` | 否 |
| `QIANXIN_EVENT_MAX_PAGES_PER_SYNC` | 单次任务最多同步页数 | `20` | 否 |
| `QIANXIN_EVENT_HTTP_TIMEOUT_SEC` | 内网 API 请求超时（秒） | `30` | 否 |

### 前端服务

前端生产镜像使用同源 `/api` 请求，并由 Nginx 反代到 `backend:8000`，无需单独配置浏览器可见的后端地址。

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
IMPERSONATION_FULL_WHITELIST_PATH=/app/app/data/official_domains/full_whitelist.csv
ACCESS_TOKEN_EXPIRE_MINUTES=1440
DEEPSEEK_API_KEY=your_deepseek_api_key
DEEPSEEK_MODEL=deepseek-v4-flash
DEEPSEEK_API_URL=https://api.deepseek.com/chat/completions

# Lazarus.day 采集模块（用 openssl rand -hex 32 生成，不要提交真实密钥）
LAZARUS_DAY_API_KEY=replace_with_a_random_64_hex_secret
LAZARUS_EVENT_SYNC_ENABLED=true
LAZARUS_EVENT_AUTO_IMPORT=false

# Qianxin 在 Windows 192.168.21.181 上运行；API Key 必须与该 Windows 用户环境一致。
QIANXIN_API_URL=http://192.168.21.181:8787
QIANXIN_API_KEY=replace_with_the_windows_qianxin_api_key
QIANXIN_EVENT_SYNC_ENABLED=true
QIANXIN_COLLECTION_TRIGGER_ENABLED=false
QIANXIN_EVENT_AUTO_IMPORT=false
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
