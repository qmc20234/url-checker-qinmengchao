// tests/integration/api_test.go
package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSingleURLCheck 测试单个URL检查
func (s *IntegrationTestSuite) TestSingleURLCheck() {
	t := s.T()

	// 构建请求
	testURL := s.testServers[0].URL
	reqURL := fmt.Sprintf("%s/api/check?urls=%s", s.server.URL, url.QueryEscape(testURL))

	// 发送请求
	resp, err := s.httpClient.Get(reqURL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 验证响应
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/event-stream")
	assert.Equal(t, "no-cache", resp.Header.Get("Cache-Control"))

	// 解析SSE响应
	messages, err := ParseSSE(resp.Body)
	require.NoError(t, err)

	// 验证SSE消息
	assert.GreaterOrEqual(t, len(messages), 2)

	var checkResult CheckResult
	for _, msg := range messages {
		switch msg.Event {
		case "check":
			err := json.Unmarshal([]byte(msg.Data), &checkResult)
			assert.NoError(t, err)
			assert.Equal(t, testURL, checkResult.URL)
			assert.Equal(t, http.StatusOK, checkResult.StatusCode)
			assert.True(t, checkResult.Success)
			assert.Greater(t, checkResult.LatencyMS, int64(0))
		case "end":
			var endMsg EndMessage
			err := json.Unmarshal([]byte(msg.Data), &endMsg)
			assert.NoError(t, err)
			assert.Equal(t, "检查完成", endMsg.Message)
		}
	}
}

// TestMultipleURLsCheck 测试多个URL批量检查
func (s *IntegrationTestSuite) TestMultipleURLsCheck() {
	t := s.T()

	// 准备多个测试URL
	var urls []string
	for i := 0; i < 3; i++ {
		urls = append(urls, s.testServers[i].URL)
	}

	// 构建请求
	encodedURLs := url.QueryEscape(strings.Join(urls, ","))
	reqURL := fmt.Sprintf("%s/api/check?urls=%s", s.server.URL, encodedURLs)

	// 发送请求
	resp, err := s.httpClient.Get(reqURL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 验证响应
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 解析SSE响应并计数
	messages, err := ParseSSE(resp.Body)
	require.NoError(t, err)

	checkCount := 0
	for _, msg := range messages {
		if msg.Event == "check" {
			checkCount++
			var result CheckResult
			err := json.Unmarshal([]byte(msg.Data), &result)
			assert.NoError(t, err)
			assert.True(t, result.StatusCode >= 200 && result.StatusCode < 600)
		}
	}

	// 应该收到3个检查结果
	assert.Equal(t, 3, checkCount)
}

// TestConcurrencyControl 测试并发控制
func (s *IntegrationTestSuite) TestConcurrencyControl() {
	t := s.T()

	// 创建10个慢响应URL
	var urls []string
	for i := 0; i < 10; i++ {
		// 使用慢响应服务器
		urls = append(urls, s.testServers[1].URL)
	}

	// 构建请求
	encodedURLs := url.QueryEscape(strings.Join(urls, ","))
	reqURL := fmt.Sprintf("%s/api/check?urls=%s", s.server.URL, encodedURLs)

	// 记录开始时间
	start := time.Now()

	// 发送请求
	resp, err := s.httpClient.Get(reqURL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 读取整个响应（确保所有检查完成）
	_, err = io.ReadAll(resp.Body)
	require.NoError(t, err)

	elapsed := time.Since(start)

	// 验证并发控制：10个慢请求，并发限制为5
	// 每个请求500ms，5个并发需要约1秒完成
	assert.Less(t, elapsed.Seconds(), 3.0)    // 应该小于3秒
	assert.Greater(t, elapsed.Seconds(), 0.8) // 应该大于0.8秒
}

// TestErrorURLHandling 测试错误URL处理
func (s *IntegrationTestSuite) TestErrorURLHandling() {
	t := s.T()

	testCases := []struct {
		name     string
		urls     []string
		expected int // 预期的检查事件数量
	}{
		{
			name:     "混合正常和错误URL",
			urls:     []string{s.testServers[0].URL, "http://invalid-domain-xyz.test", s.testServers[2].URL},
			expected: 3, // 应该收到3个结果（包括错误）
		},
		{
			name:     "全部错误URL",
			urls:     []string{"http://not-exist-1.test", "http://not-exist-2.test"},
			expected: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 构建请求
			encodedURLs := url.QueryEscape(strings.Join(tc.urls, ","))
			reqURL := fmt.Sprintf("%s/api/check?urls=%s", s.server.URL, encodedURLs)

			// 发送请求
			resp, err := s.httpClient.Get(reqURL)
			require.NoError(t, err)
			defer resp.Body.Close()

			// 解析响应
			messages, err := ParseSSE(resp.Body)
			require.NoError(t, err)

			// 统计检查事件
			checkCount := 0
			for _, msg := range messages {
				if msg.Event == "check" {
					checkCount++
				}
			}

			assert.Equal(t, tc.expected, checkCount)
		})
	}
}

// TestSSLCertCheck 测试SSL证书检查
func (s *IntegrationTestSuite) TestSSLCertCheck() {
	t := s.T()

	// 使用HTTPS测试服务器
	httpsServer := s.testServers[4]
	reqURL := fmt.Sprintf("%s/api/check?urls=%s", s.server.URL, url.QueryEscape(httpsServer.URL))

	// 发送请求
	resp, err := s.httpClient.Get(reqURL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// 解析响应
	messages, err := ParseSSE(resp.Body)
	require.NoError(t, err)

	// 验证SSL证书信息
	for _, msg := range messages {
		if msg.Event == "check" {
			var result CheckResult
			err := json.Unmarshal([]byte(msg.Data), &result)
			assert.NoError(t, err)

			// HTTPS服务器应该返回证书信息
			assert.NotEmpty(t, result.CertExpiry)
			assert.Greater(t, result.DaysLeft, 0)
			break
		}
	}
}

// TestInvalidParameters 测试无效参数
func (s *IntegrationTestSuite) TestInvalidParameters() {
	t := s.T()

	testCases := []struct {
		name       string
		query      string
		expectCode int
	}{
		{
			name:       "没有urls参数",
			query:      "",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "空的urls参数",
			query:      "urls=",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "无效的URL格式",
			query:      "urls=not-a-valid-url",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "超过URL数量限制",
			query:      fmt.Sprintf("urls=%s", strings.Repeat("http://example.com,", 101)),
			expectCode: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqURL := fmt.Sprintf("%s/api/check?%s", s.server.URL, tc.query)

			resp, err := s.httpClient.Get(reqURL)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectCode, resp.StatusCode)
		})
	}
}
