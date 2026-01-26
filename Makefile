# Makefile
.PHONY: test test-integration test-unit coverage help

# 默认目标
help:
	@echo "可用命令:"
	@echo "  make test           # 运行所有测试"
	@echo "  make test-integration # 运行集成测试"
	@echo "  make test-unit      # 运行单元测试"
	@echo "  make coverage       # 生成覆盖率报告"
	@echo "  make coverage-open  # 生成并打开覆盖率报告"
	@echo "  make clean          # 清理"

# 运行所有测试
test: test-unit test-integration

# 运行集成测试
test-integration:
	@echo "运行集成测试..."
	@./scripts/run_integration_tests.sh

# 运行集成测试（带性能测试）
test-integration-perf:
	@./scripts/run_integration_tests.sh --perf

# 运行单元测试
test-unit:
	@echo "运行单元测试..."
	@go test ./tests/unit -v -count=1

# 生成覆盖率报告
coverage:
	@./scripts/coverage.sh

# 生成并打开覆盖率报告
coverage-open:
	@./scripts/coverage.sh --open

# 清理
clean:
	@rm -f coverage.out coverage.html
	@go clean -testcache
	@echo "清理完成"