# 多阶段构建 Dockerfile
# 第一阶段：构建阶段
FROM node:20-alpine AS builder

# 设置工作目录
WORKDIR /app

# 安装 pnpm
RUN corepack enable && corepack prepare pnpm@10.17.1 --activate

# 复制包管理文件
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./

# 安装依赖（使用 pnpm 的冻结锁文件）
RUN pnpm install --no-frozen-lockfile

# 复制源代码
COPY . .

# 构建应用
RUN pnpm build

# 第二阶段：运行阶段
FROM nginx:alpine

# 删除默认配置
RUN rm /etc/nginx/conf.d/default.conf

# 创建必要的目录（用于 nginx.conf 中的配置）
RUN mkdir -p /var/log/nginx /run/nginx /etc/nginx/modules-enabled /etc/nginx/sites-enabled

# 创建 www-data 用户和组（nginx.conf 中指定的用户）
# nginx:alpine 默认使用 nginx 用户，但为了兼容自定义 nginx.conf，创建 www-data
# 使用 || true 避免用户已存在时构建失败
RUN addgroup -g 33 -S www-data || true && \
    adduser -u 33 -G www-data -S -s /sbin/nologin -D www-data || true

# 复制 nginx 站点配置文件
COPY default.conf /etc/nginx/conf.d/default.conf

# 从构建阶段复制构建产物
COPY --from=builder /app/dist /usr/share/nginx/html

# 设置文件权限
RUN chmod -R 755 /usr/share/nginx/html

# 暴露端口
EXPOSE 80

# 启动 nginx
CMD ["nginx", "-g", "daemon off;"]