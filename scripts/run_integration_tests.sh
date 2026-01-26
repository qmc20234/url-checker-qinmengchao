#!/bin/bash
# scripts/run_integration_tests.sh

set -e  # 遇到错误立即退出

echo "🚀 开始运行集成测试..."

# 设置测试环境变量
export GO_ENV=test
export LOG_LEVEL=warn

# 清理之前的测试缓存
echo "🧹 清理测试缓存..."
go clean -testcache

# 检查是否安装了必要的工具
if ! command -v go &> /dev/null; then
    echo "❌ Go 未安装"
    exit 1
fi

# 运行集成测试
echo "📋 运行集成测试..."
go test ./tests/integration -v -count=1 -timeout=5m $@

# 可选：运行性能测试
if [[ "$1" == "--perf" ]] || [[ "$2" == "--perf" ]]; then
    echo "⚡ 运行性能测试..."
    go test ./tests/integration -v -run="TestLoadTest|TestConcurrentRequests" -timeout=10m
fi

echo "✅ 集成测试完成"