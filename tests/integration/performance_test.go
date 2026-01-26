// tests/integration/performance_test.go
package integration

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrentRequests 测试并发请求
func (s *IntegrationTestSuite) TestConcurrentRequests() {
	t := s.T()

	// 准备测试数据
	urls := []string{
		s.testServers[0].URL, // 正常响应
		s.testServers[1].URL, // 慢响应
		s.testServers[2].URL, // 错误响应
	}
	encodedURLs := url.QueryEscape(strings.Join(urls, ","))

	concurrentRequests := 10
	var wg sync.WaitGroup
	start := time.Now()

	// 并发发送请求
	for i := 0; i < concurrentRequests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			reqURL := fmt.Sprintf("%s/api/check?urls=%s", s.server.URL, encodedURLs)
			resp, err := s.httpClient.Get(reqURL)
			if err != nil {
				t.Errorf("请求 %d 失败: %v", index, err)
				return
			}
			defer resp.Body.Close()

			// 读取响应确保完成
			io.ReadAll(resp.Body)
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	// 验证性能
	t.Logf("完成 %d 个并发请求，耗时: %v", concurrentRequests, elapsed)
	assert.Less(t, elapsed.Seconds(), 10.0, "并发请求应在10秒内完成")
}

// TestLoadTest 负载测试
func (s *IntegrationTestSuite) TestLoadTest() {
	t := s.T()

	if testing.Short() {
		t.Skip("跳过负载测试")
	}

	// 准备100个URL（包含混合类型）
	var testURLs []string
	for i := 0; i < 20; i++ {
		testURLs = append(testURLs,
			s.testServers[0].URL, // 正常
			s.testServers[1].URL, // 慢
			s.testServers[2].URL, // 错误
			s.testServers[3].URL, // 重定向
			s.testServers[4].URL, // HTTPS
		)
	}

	encodedURLs := url.QueryEscape(strings.Join(testURLs[:50], ",")) // 前50个URL

	// 记录开始时间
	start := time.Now()

	// 发送大请求
	reqURL := fmt.Sprintf("%s/api/check?urls=%s", s.server.URL, encodedURLs)
	resp, err := s.httpClient.Get(reqURL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 解析并计数响应
	messages, err := ParseSSE(resp.Body)
	require.NoError(t, err)

	checkCount := 0
	for _, msg := range messages {
		if msg.Event == "check" {
			checkCount++
		}
	}

	elapsed := time.Since(start)

	// 验证
	assert.Equal(t, 50, checkCount, "应该检查50个URL")
	t.Logf("检查 %d 个URL耗时: %v", checkCount, elapsed)
	assert.Less(t, elapsed.Seconds(), 30.0, "50个URL应在30秒内完成")
}
