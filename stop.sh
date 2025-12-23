#!/bin/bash

# ATDV Pro 项目停止脚本
# 使用方法: ./stop.sh [--remove-volumes]

set -e

echo "=========================================="
echo "  ATDV Pro - 停止服务"
echo "=========================================="
echo ""

# 检查 Docker Compose 是否安装
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ 错误: 未检测到 Docker Compose"
    exit 1
fi

# 检查是否要删除数据卷
if [ "$1" == "--remove-volumes" ] || [ "$1" == "-v" ]; then
    echo "⚠️  警告: 将删除所有数据卷，所有数据将被永久删除！"
    read -p "   确认继续? (yes/no) " -r
    echo
    if [[ $REPLY == "yes" ]]; then
        echo "🛑 停止服务并删除数据卷..."
        docker-compose down -v
        echo "✅ 服务已停止，数据卷已删除"
    else
        echo "❌ 操作已取消"
        exit 1
    fi
else
    echo "🛑 停止服务..."
    docker-compose down
    echo "✅ 服务已停止"
    echo ""
    echo "💡 提示: 数据卷已保留，重新启动后数据仍然存在"
    echo "   如需删除数据卷，请使用: ./stop.sh --remove-volumes"
fi

echo ""

