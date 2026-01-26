#!/bin/bash
# scripts/coverage.sh

set -e

echo "📊 生成测试覆盖率报告..."

# 清理旧的覆盖率文件
rm -f coverage.out coverage.html

# 运行测试并生成覆盖率数据
echo "🧪 运行测试..."
go test ./tests/integration -coverprofile=coverage.out -covermode=atomic -count=1

# 检查是否生成覆盖率文件
if [ ! -f coverage.out ]; then
    echo "❌ 未生成覆盖率文件"
    exit 1
fi

# 生成HTML报告
echo "📈 生成HTML报告..."
go tool cover -html=coverage.out -o coverage.html

# 显示覆盖率摘要
echo "📋 覆盖率摘要:"
echo "================================================================="
go tool cover -func=coverage.out
echo "================================================================="

# 显示总体覆盖率
echo ""
TOTAL_COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}')
echo "🎯 总体覆盖率: ${TOTAL_COVERAGE}"

# 打开报告（可选，Mac系统）
if [[ "$1" == "--open" ]] && [[ "$OSTYPE" == "darwin"* ]]; then
    open coverage.html
fi

echo "✅ 覆盖率报告已生成:"
echo "   - coverage.out (原始数据)"
echo "   - coverage.html (HTML报告)"