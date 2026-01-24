// 文件：tests/client_test.go
package tests // 包名可以是 tests 或 main_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
)

// 正确的测试函数：以 Test 开头，接收 *testing.T 参数
func TestHealthCheck(t *testing.T) {
	resp, err := http.Get("http://localhost:8080/api/health")
	if err != nil {
		t.Fatalf("健康检查请求失败: %v", err) // 使用 t.Fatalf 报告失败
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("健康检查响应: %s\n", body) // 使用 Printf 在测试时输出

	// 断言状态码为 200
	if resp.StatusCode != http.StatusOK {
		t.Errorf("期望状态码 200, 实际得到 %d", resp.StatusCode)
	}
}

func TestBatchCheck(t *testing.T) {
	payload := map[string][]string{
		"urls": {"https://httpbin.org/status/200", "https://httpbin.org/status/404"},
	}
	jsonData, _ := json.Marshal(payload)

	resp, err := http.Post("http://localhost:8080/api/check", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatalf("批量检查请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("批量检查响应: %s\n", body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("期望状态码 200, 实际得到 %d", resp.StatusCode)
	}
}
