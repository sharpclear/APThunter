#!/bin/bash

# ATDV Pro 项目启动脚本
# 使用方法: ./start.sh

set -e

echo "=========================================="
echo "  ATDV Pro - 恶意域名检测系统"
echo "  启动脚本"
echo "=========================================="
echo ""

# 检查 Docker 是否安装
if ! command -v docker &> /dev/null; then
    echo "❌ 错误: 未检测到 Docker，请先安装 Docker"
    echo "   访问 https://docs.docker.com/get-docker/ 获取安装指南"
    exit 1
fi

# 检查 Docker Compose 是否安装
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ 错误: 未检测到 Docker Compose，请先安装 Docker Compose"
    echo "   访问 https://docs.docker.com/compose/install/ 获取安装指南"
    exit 1
fi

# 检查端口占用
check_port() {
    local port=$1
    local service=$2
    
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1 || netstat -an 2>/dev/null | grep -q ":$port.*LISTEN"; then
        echo "⚠️  警告: 端口 $port 已被占用，$service 服务可能无法启动"
        read -p "   是否继续? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

echo "🔍 检查端口占用..."
check_port 80 "前端"
check_port 8000 "后端"
check_port 3306 "MySQL"
check_port 9000 "MinIO API"
check_port 9001 "MinIO 控制台"
echo "✅ 端口检查完成"
echo ""

# 检查 .env 文件
if [ ! -f .env ]; then
    echo "ℹ️  未找到 .env 文件，将使用 docker-compose.yml 中的默认配置"
    echo "   如需自定义配置，请创建 .env 文件（参考 ENV.md）"
    echo ""
fi

# 启动服务
echo "🚀 启动 Docker Compose 服务..."
docker-compose up -d

echo ""
echo "⏳ 等待服务启动..."
sleep 5

# 检查服务状态
echo ""
echo "📊 服务状态:"
docker-compose ps

echo ""
echo "📝 查看日志命令:"
echo "   docker-compose logs -f"
echo ""

echo "🌐 访问地址:"
echo "   前端应用:     http://localhost"
echo "   后端 API:     http://localhost:8000/api"
echo "   API 文档:     http://localhost:8000/docs"
echo "   MinIO 控制台: http://localhost:9001"
echo "   用户名: minioadmin"
echo "   密码:   123456789"
echo ""

echo "✅ 启动完成！"
echo ""
echo "💡 提示:"
echo "   - 查看日志: docker-compose logs -f"
echo "   - 停止服务: docker-compose down"
echo "   - 重启服务: docker-compose restart"
echo ""

