// tests/integration/integration_test.go
package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"url-checker/cmd/app"
	"url-checker/internal/config"
)

// IntegrationTestSuite 集成测试套件
type IntegrationTestSuite struct {
	suite.Suite
	app         *app.Application
	server      *httptest.Server
	httpClient  *http.Client
	testServers []*httptest.Server
}

// SetupSuite 测试套件初始化
func (s *IntegrationTestSuite) SetupSuite() {
	// 1. 创建测试配置
	cfg := &config.Config{
		Server: config.ServerConfig{
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		Log: config.LogConfig{
			Level:  "info",
			Format: "json",
		},
		Checker: config.CheckerConfig{
			MaxConcurrent: 5,
			Timeout:       10 * time.Second,
			RetryInterval: 1 * time.Second,
			MaxRedirects:  5,
			UserAgent:     "URL-Checker-Integration-Test",
		},
	}

	// 2. 创建测试目标服务器
	s.setupTestTargetServers()

	// 3. 初始化应用
	var err error
	s.app, err = app.NewApplication(cfg)
	require.NoError(s.T(), err)

	// 4. 启动测试服务器
	s.server = httptest.NewServer(s.app.GetRouter())

	// 启用HTTP/2
	s.httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}

	s.T().Logf("测试服务器启动在: %s", s.server.URL)

	// 5. 创建测试HTTP客户端
	s.httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}
}

// 设置测试目标服务器
func (s *IntegrationTestSuite) setupTestTargetServers() {
	// 正常响应服务器
	normalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	s.testServers = append(s.testServers, normalServer)

	// 慢响应服务器（模拟延迟）
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Slow Response"))
	}))
	s.testServers = append(s.testServers, slowServer)

	// 错误响应服务器
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	s.testServers = append(s.testServers, errorServer)

	// 重定向服务器
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Redirect Target"))
	}))
	s.testServers = append(s.testServers, redirectServer)

	// HTTPS测试服务器（带证书）
	httpsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("HTTPS OK"))
	}))
	s.testServers = append(s.testServers, httpsServer)
}

// TearDownSuite 测试套件清理
func (s *IntegrationTestSuite) TearDownSuite() {
	// 关闭测试服务器
	for _, server := range s.testServers {
		server.Close()
	}

	// 关闭主服务器
	if s.server != nil {
		s.server.Close()
	}

	// 关闭应用
	if s.app != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.app.Shutdown(ctx)
	}
}

// TestIntegrationSuite 运行测试套件
func TestIntegrationSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过集成测试")
	}
	suite.Run(t, new(IntegrationTestSuite))
}
