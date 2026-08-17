# APTHunter 远程虚拟机部署简要流程

本文说明“先把同一提交推送到 GitHub，再由本地构建并上传 Linux 镜像，最后在虚拟机加载并增量替换应用容器”的流程。部署目标是让远程虚拟机上的代码、镜像和数据库结构与本次发布版本对齐，同时保留 MySQL、MinIO、Redis 和全部数据卷。

## 1. 确认本地发布版本

镜像、Git 代码和数据库结构必须来自同一个版本。先确认当前分支和提交状态：

```bash
git status
git branch --show-current
git rev-parse --short=12 HEAD
```

如果本次镜像包含了尚未提交的代码改动，应先提交并推送到 GitHub，再重新构建并验证镜像。不要让远程代码停留在一个提交，而镜像来自另一个未提交状态。

```bash
git add <changed-files>
git commit -m "描述本次部署内容"
git push origin <branch>
```

建议设置一个部署标识，后续镜像包、数据库备份和远程命令都使用同一个值：

```bash
export DEPLOY_TAG=manual-$(date +%Y%m%d-%H%M)
```

## 2. 本地打包并上传镜像

如果镜像尚未从本次 Git 提交构建，直接使用 `--build` 完成 Linux/amd64 构建、打包和上传：

```bash
bash scripts/deploy-local.sh \
  --build \
  --tag "$DEPLOY_TAG" \
  --remote-host 192.168.32.219 \
  --remote-user mlz \
  --ssh-key ~/.ssh/apthunter_vm_ed25519
```

如果已经手工构建并验证过全部镜像，可先 dry-run，确认脚本选择的镜像会被重命名为远程 Compose 使用的 `apthunter-*` 镜像名：

```bash
bash scripts/deploy-local.sh --dry-run --tag "$DEPLOY_TAG"
```

确认无误后省略 `--build`，只打包并上传已有镜像：

```bash
bash scripts/deploy-local.sh \
  --tag "$DEPLOY_TAG" \
  --remote-host <远程IP或域名> \
  --remote-port 22 \
  --remote-user <远程用户>
```

如果使用 SSH key：

```bash
bash scripts/deploy-local.sh \
  --tag "$DEPLOY_TAG" \
  --remote-host <远程IP或域名> \
  --remote-port 22 \
  --remote-user <远程用户> \
  --ssh-key ~/.ssh/id_ed25519
```

脚本会生成并上传：

- `apthunter-images-${DEPLOY_TAG}.tar.gz`
- `apthunter-images-${DEPLOY_TAG}.tar.gz.sha256`
- `manifest-${DEPLOY_TAG}.env`

归档包含 MySQL、backend、Celery worker、Celery beat、Lazarus collector 和 frontend 六个项目镜像。Redis 与 MinIO 继续使用公开镜像，不装入归档。

默认远程上传目录是：

```text
/home/mlz/APTHunter/releases
```

如远程项目目录不同，请优先使用 `--remote-project-dir` 指定实际项目目录；上传目录会默认跟随为该目录下的 `releases`。如果上传目录需要单独放置，再使用 `--remote-upload-dir` 指定。

## 3. 通过 GitHub 对齐远程代码

登录远程虚拟机：

```bash
ssh -p 22 <远程用户>@<远程IP或域名>
cd /home/mlz/APTHunter
```

先确认远程没有未处理的本地改动：

```bash
git status
```

再拉取与本地镜像对应的分支：

```bash
git fetch origin
git checkout <branch>
git pull --ff-only origin <branch>
git rev-parse --short=12 HEAD
```

远程 `HEAD` 应与本地本次打包镜像时的提交一致。可以查看上传的 manifest 辅助核对：

```bash
cat releases/manifest-${DEPLOY_TAG}.env
```

注意：远程 `.env` 通常保存部署环境的密钥、邮箱、飞书、LLM 等配置，不通过 GitHub 或镜像包覆盖。

首次部署 Lazarus 前，至少确认 `.env` 中有以下配置：

```dotenv
LAZARUS_DAY_API_KEY=<至少32字符，建议使用 openssl rand -hex 32>
LAZARUS_EVENT_SYNC_ENABLED=true
LAZARUS_EVENT_AUTO_IMPORT=false
```

如果启用了 Qianxin 同步，远程脚本还会要求 `QIANXIN_API_URL` 和 `QIANXIN_API_KEY` 有效。这里的 URL 应填写虚拟机能访问到的本机内网地址，而不是 `127.0.0.1`。

## 4. 对齐数据库

数据库对齐分两种情况，按实际部署目标选择一种。

### 情况 A：只对齐数据库结构

如果远程已有数据需要保留，只让远程执行数据库 bootstrap 即可。远程部署脚本默认会处理：

- 启动 MySQL、Redis、MinIO 基础服务
- 通过后端镜像执行 `/app/scripts/db_bootstrap.py`
- 对齐当前表结构、当前官方模型/初始账号数据，并记录已由 bootstrap 覆盖的历史 migration
- 自动执行未来新增且尚未记录的 migration
- 重建 backend、celery-worker、celery-beat、lazarus-collector、frontend 容器

这种情况不需要导入本地完整数据库，直接执行第 5 步即可。

### 情况 B：用本地数据库覆盖远程数据库

仅在远程是测试环境，且确认可以覆盖远程数据时使用。生产环境不要直接用本地库覆盖。

本地导出数据库：

```bash
mkdir -p .deploy/db
docker compose exec -T mysql sh -c \
  'mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction --routines --triggers "$MYSQL_DATABASE"' \
  | gzip > ".deploy/db/apthunter_new-${DEPLOY_TAG}.sql.gz"
```

上传数据库 dump：

```bash
scp -P 22 ".deploy/db/apthunter_new-${DEPLOY_TAG}.sql.gz" \
  <远程用户>@<远程IP或域名>:/home/mlz/APTHunter/releases/
```

远程导入前，先备份当前远程数据库：

```bash
cd /home/mlz/APTHunter
mkdir -p backups
docker compose -p apthunter exec -T mysql sh -c \
  'mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction --routines --triggers "$MYSQL_DATABASE"' \
  | gzip > "backups/apthunter_new-before-${DEPLOY_TAG}.sql.gz"
```

停止应用服务，避免导入时还有任务写库：

```bash
docker compose -p apthunter stop frontend celery-worker backend
```

导入本地 dump：

```bash
gzip -dc "releases/apthunter_new-${DEPLOY_TAG}.sql.gz" \
  | docker compose -p apthunter exec -T mysql sh -c \
      'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" "$MYSQL_DATABASE"'
```

数据库 dump 只包含 MySQL 数据，不包含 MinIO 对象文件。若检测结果、上传文件或训练数据依赖 MinIO，需要另行同步 MinIO 数据。

## 5. 远程加载镜像并启动容器

在远程项目目录执行：

```bash
cd /home/mlz/APTHunter
bash scripts/deploy-remote.sh --tag "$DEPLOY_TAG"
```

脚本会：

- 校验远程 Git 提交与镜像 manifest 一致，并拒绝有未提交的 tracked 修改
- 校验 Lazarus 密钥；启用 Qianxin 时同时校验 Qianxin URL 和密钥
- 检查是否存在正在执行的分析、训练或 Lazarus 采集任务
- 在 `backups/` 创建迁移前的 MySQL 压缩备份
- 为当前应用容器镜像保留 `rollback-${DEPLOY_TAG}` 标签
- 校验镜像包 sha256
- `docker load` 导入镜像
- 按 manifest 中的 `TARGET_IMAGES` 确认目标镜像存在并校验为 `linux/amd64`
- 拉取或复用 Redis、MinIO 镜像
- 使用 `--no-recreate` 确保 MySQL、Redis、MinIO 在线，不因加载了新镜像而替换现有容器
- 通过后端镜像执行 `/app/scripts/db_bootstrap.py`，完成表结构兼容、初始账号/模型数据和后续 migration
- 使用 `--no-build --no-deps --force-recreate` 分阶段仅重建应用容器，避免 Compose 因镜像标签变化替换基础设施依赖
- 等待 backend、celery-worker、celery-beat、lazarus-collector、frontend 健康检查
- 如存在 `scripts/compose-verify.sh`，执行接口验证

这不是“增量镜像”：上传的仍是完整镜像。增量指部署时只替换应用容器，不执行 `docker compose down`，也不删除或重建数据卷。正常情况下 MySQL、Redis、MinIO 不停机；应用容器会有一次短暂重启。

如果只想先执行数据库 bootstrap/migration，不加载镜像和重建应用：

```bash
bash scripts/deploy-remote.sh --migrations-only
```

## 6. 部署后检查

查看容器状态：

```bash
docker compose -p apthunter ps
```

查看关键日志：

```bash
docker compose -p apthunter logs --tail=100 backend
docker compose -p apthunter logs --tail=100 celery-worker
docker compose -p apthunter logs --tail=100 celery-beat
docker compose -p apthunter logs --tail=100 lazarus-collector
docker compose -p apthunter logs --tail=100 frontend
```

如果远程机器开放 80 端口，浏览器访问：

```text
http://<远程IP或域名>/
```

远程服务端口约定：

- Web：`80`
- 后端：`127.0.0.1:8000`
- MySQL：`127.0.0.1:3307`
- MinIO：`127.0.0.1:9000/9001`

## 7. 回滚思路

当前脚本不会自动回滚。若部署失败，优先保留现场并查看日志。

常见回退方式：

1. 本次部署前的应用镜像会保留为 `rollback-${DEPLOY_TAG}`。如需立即恢复镜像，先检查标签，再逐一重新标记为 `latest`：

```bash
for service in backend celery-worker celery-beat lazarus-collector frontend; do
  rollback="apthunter-${service}:rollback-${DEPLOY_TAG}"
  docker image inspect "$rollback" >/dev/null 2>&1 || continue
  docker tag "$rollback" "apthunter-${service}:latest"
done
docker compose -p apthunter up -d --no-build --no-deps --force-recreate \
  backend lazarus-collector celery-worker celery-beat frontend
```

2. 远程代码切回上一个 Git 提交或分支。
3. 或重新执行上一版镜像包：

```bash
bash scripts/deploy-remote.sh --tag <上一版DEPLOY_TAG>
```

4. 如迁移必须回退，需要确认后再恢复部署前备份：

```bash
gzip -dc "backups/apthunter_new-before-${DEPLOY_TAG}.sql.gz" \
  | docker compose -p apthunter exec -T mysql sh -c \
      'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" "$MYSQL_DATABASE"'
```

恢复数据库属于高风险操作，执行前必须确认目标环境和备份文件。
