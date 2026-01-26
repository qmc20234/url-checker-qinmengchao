package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/sourcegraph/conc/pool"
)

// --- 优化1: 职责分离的配置结构 ---
type HTTPConfig struct {
	Timeout        time.Duration
	MaxRetries     int
	RetryInterval  time.Duration
	MaxRedirects   int
	UserAgent      string
	AllowInsecure  bool
	FollowRedirect bool
	// 连接池配置
	TLSHandshakeTimeout time.Duration
	MaxIdleConnsPerHost int
	IdleConnTimeout     time.Duration
}

type PoolConfig struct {
	MaxConcurrent int
	BatchTimeout  time.Duration // 整个批次的超时
}

// CheckerConfig 顶层配置（组合各子配置）
type CheckerConfig struct {
	HTTP HTTPConfig
	Pool PoolConfig
	SSL  SSLConfig
}

// Validate 配置验证
func (c *CheckerConfig) Validate() error {
	if c.Pool.MaxConcurrent <= 0 {
		return fmt.Errorf("Pool.MaxConcurrent must be > 0")
	}
	if c.HTTP.Timeout <= 0 {
		return fmt.Errorf("HTTP.Timeout must be > 0")
	}
	// if c.SSL.Enabled && c.SSL.Timeout <= 0 {
	// 	return fmt.Errorf("SSL.Timeout must be > 0 when SSL enabled")
	// }
	return nil
}

// DefaultCheckerConfig 默认配置
func DefaultCheckerConfig() CheckerConfig {
	return CheckerConfig{
		HTTP: HTTPConfig{
			Timeout:             10 * time.Second,
			MaxRetries:          3,
			RetryInterval:       100 * time.Millisecond,
			MaxRedirects:        5,
			UserAgent:           "URL-Checker/1.0",
			AllowInsecure:       false,
			FollowRedirect:      true,
			TLSHandshakeTimeout: 5 * time.Second,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Pool: PoolConfig{
			MaxConcurrent: 50,
			BatchTimeout:  5 * time.Minute,
		},
		SSL: SSLConfig{
			// Enabled:                true,
			Timeout:                5 * time.Second,
			InsecureSkipVerify:     true, // 仅检查，不验证
			VerifyCertificateChain: false,
			MinTLSVersion:          tls.VersionTLS12,
		},
	}
}

// --- 优化2: HTTP客户端工厂（提高可测试性） ---
type HTTPClientFactory struct {
	config HTTPConfig
}

func NewHTTPClientFactory(config HTTPConfig) *HTTPClientFactory {
	return &HTTPClientFactory{config: config}
}

func (f *HTTPClientFactory) Create() *resty.Client {
	client := resty.New()
	client.SetTimeout(f.config.Timeout)
	client.SetRetryCount(f.config.MaxRetries)
	client.SetRetryWaitTime(f.config.RetryInterval)
	client.SetRetryMaxWaitTime(10 * time.Second)

	if f.config.UserAgent != "" {
		client.SetHeader("User-Agent", f.config.UserAgent)
	}

	// 重定向策略
	if !f.config.FollowRedirect {
		client.SetRedirectPolicy(resty.NoRedirectPolicy())
	} else if f.config.MaxRedirects > 0 {
		client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(f.config.MaxRedirects))
	}

	// 传输层配置
	transport := &http.Transport{
		TLSHandshakeTimeout: f.config.TLSHandshakeTimeout,
		MaxIdleConnsPerHost: f.config.MaxIdleConnsPerHost,
		IdleConnTimeout:     f.config.IdleConnTimeout,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: f.config.AllowInsecure,
		},
	}
	client.SetTransport(transport)

	// 指数退避重试
	client.SetRetryAfter(func(c *resty.Client, r *resty.Response) (time.Duration, error) {
		attempt := r.Request.Attempt
		delay := time.Duration(100*(1<<uint(attempt))) * time.Millisecond
		if delay > 10*time.Second {
			delay = 10 * time.Second
		}
		// 添加抖动
		jitter := time.Duration(float64(delay) * 0.1)
		delay = delay - jitter + time.Duration(float64(jitter)*2)
		return delay, nil
	})

	return client
}

// --- 优化3: 增强的检查器结构 ---
type Checker struct {
	client     *resty.Client
	sslChecker *SSLChecker
	config     CheckerConfig
	logger     zerolog.Logger
	metrics    *EnhancedMetrics
	mu         sync.RWMutex
	activeJobs int
}

// 增强的CheckResult（支持追踪）
type CheckResult struct {
	URL        string        `json:"url"`
	Host       string        `json:"host"`     // 提取的主机名
	BatchID    string        `json:"batch_id"` // 所属批次ID
	CheckID    string        `json:"check_id"` // 本次检查唯一ID
	Timestamp  time.Time     `json:"timestamp"`
	StatusCode int           `json:"status_code"`
	Success    bool          `json:"success"`
	Latency    time.Duration `json:"latency_ms"`
	Error      string        `json:"error,omitempty"`
	CertExpiry *time.Time    `json:"cert_expiry,omitempty"`
	DaysLeft   int           `json:"days_left,omitempty"`
	RetryCount int           `json:"retry_count,omitempty"`
}

// 增强的指标收集
type EnhancedMetrics struct {
	TotalChecks      int64            `json:"total_checks"`
	FailedChecks     int64            `json:"failed_checks"`
	ActiveJobs       int              `json:"active_jobs"`
	StatusCodes      map[int]int64    `json:"status_codes"`      // 状态码分布
	HostChecks       map[string]int64 `json:"host_checks"`       // 按主机统计
	ErrorTypes       map[string]int64 `json:"error_types"`       // 错误类型统计
	LatencyHistogram []time.Duration  `json:"latency_histogram"` // 延迟直方图（简化版）
}

func NewEnhancedMetrics() *EnhancedMetrics {
	return &EnhancedMetrics{
		StatusCodes: make(map[int]int64),
		HostChecks:  make(map[string]int64),
		ErrorTypes:  make(map[string]int64),
	}
}

// --- 优化4: 重构的检查器构造函数 ---
func NewChecker(config CheckerConfig, logger zerolog.Logger) (*Checker, error) {
	// 配置验证
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid checker config: %w", err)
	}

	// 创建HTTP客户端
	clientFactory := NewHTTPClientFactory(config.HTTP)
	client := clientFactory.Create()

	// 创建SSL检查器（如果启用）
	var sslChecker *SSLChecker
	// if config.SSL.Enabled {
	sslConfig := SSLConfig{
		Timeout:                config.SSL.Timeout,
		InsecureSkipVerify:     config.SSL.InsecureSkipVerify,
		VerifyCertificateChain: config.SSL.VerifyCertificateChain,
		MinTLSVersion:          config.SSL.MinTLSVersion,
	}
	var err error
	sslChecker, err = NewSSLChecker(sslConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSL checker: %w", err)
	}
	// }

	c := &Checker{
		client:     client,
		sslChecker: sslChecker,
		config:     config,
		logger:     logger.With().Str("component", "checker").Logger(),
		metrics:    NewEnhancedMetrics(),
	}

	c.logger.Info().
		Int("max_concurrent", config.Pool.MaxConcurrent).
		Dur("http_timeout", config.HTTP.Timeout).
		// Bool("ssl_enabled", config.SSL.Enabled).
		Msg("URL检查器初始化完成")

	return c, nil
}

// --- 优化5: 增强的单个URL检查（支持完整追踪） ---
func (c *Checker) CheckURL(ctx context.Context, urlStr string, batchID, checkID string) CheckResult {
	// 开始检查
	start := time.Now()
	host := extractHost(urlStr)

	// 更新指标
	c.mu.Lock()
	c.activeJobs++
	c.metrics.ActiveJobs = c.activeJobs
	c.metrics.TotalChecks++
	c.metrics.HostChecks[host]++
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.activeJobs--
		c.metrics.ActiveJobs = c.activeJobs
		c.mu.Unlock()
	}()

	// 创建本次检查的专用Logger
	checkLogger := c.logger.With().
		Str("check_id", checkID).
		Str("batch_id", batchID).
		Str("url", urlStr).
		Str("host", host).
		Logger()

	checkLogger.Debug().Msg("开始检查URL")

	// 准备结果
	result := CheckResult{
		URL:       urlStr,
		Host:      host,
		BatchID:   batchID,
		CheckID:   checkID,
		Timestamp: time.Now(),
	}

	// 执行HTTP请求
	resp, err := c.client.R().
		SetContext(ctx).
		SetDoNotParseResponse(true).
		Head(urlStr)

	result.Latency = time.Since(start)

	// 记录延迟到直方图（简化版，记录最近100次）
	c.mu.Lock()
	if len(c.metrics.LatencyHistogram) < 100 {
		c.metrics.LatencyHistogram = append(c.metrics.LatencyHistogram, result.Latency)
	}
	c.mu.Unlock()

	if err != nil {
		// 失败处理
		c.mu.Lock()
		c.metrics.FailedChecks++
		errorType := extractErrorType(err)
		c.metrics.ErrorTypes[errorType]++
		c.mu.Unlock()

		result.Error = err.Error()
		result.Success = false

		checkLogger.Warn().
			Err(err).
			Str("error_type", errorType).
			Dur("latency", result.Latency).
			Msg("URL检查失败")

		return result
	}
	defer resp.RawResponse.Body.Close()

	// 成功处理
	result.StatusCode = resp.StatusCode()
	result.Success = resp.IsSuccess()
	result.RetryCount = resp.Request.Attempt

	// 记录状态码分布
	c.mu.Lock()
	c.metrics.StatusCodes[result.StatusCode]++
	c.mu.Unlock()

	checkLogger.Debug().
		Int("status_code", result.StatusCode).
		Dur("latency", result.Latency).
		Int("retry_count", result.RetryCount).
		Msg("URL检查完成")

	// SSL检查
	if c.sslChecker != nil {
		// 判断是否需要SSL检查，并处理可能出现的错误
		required, err := IsSSLRequired(urlStr)
		if err != nil {
			// 如果URL格式有问题，记录警告并跳过SSL检查
			checkLogger.Warn().
				Err(err).
				Msg("无法判断是否需要SSL检查，跳过")
		} else if required {
			certInfo, err := c.sslChecker.Check(ctx, urlStr)
			if err == nil {
				result.CertExpiry = &certInfo.Expiry
				result.DaysLeft = certInfo.DaysLeft

				checkLogger.Debug().
					Time("cert_expiry", certInfo.Expiry).
					Int("days_left", certInfo.DaysLeft).
					Msg("SSL证书检查完成")
			} else {
				checkLogger.Warn().
					Err(err).
					Msg("SSL证书检查失败")
			}
		}
	}

	return result
}

// --- 优化6: 增强的批量检查（支持完整追踪） ---
func (c *Checker) BatchCheck(ctx context.Context, urls []string) []CheckResult {
	// 为整个批次生成唯一ID
	batchID := generateBatchID()
	batchLogger := c.logger.With().
		Str("batch_id", batchID).
		Int("url_count", len(urls)).
		Logger()

	batchLogger.Info().Msg("开始批量URL检查")

	batchStart := time.Now()

	// 创建Worker Pool
	p := pool.New().WithMaxGoroutines(c.config.Pool.MaxConcurrent)

	// 准备结果存储和通道
	results := make([]CheckResult, len(urls))
	resultCh := make(chan indexedResult, len(urls))

	// 设置批次超时
	batchCtx, cancel := context.WithTimeout(ctx, c.config.Pool.BatchTimeout)
	defer cancel()

	// 分发任务
	for i, url := range urls {
		i, url := i, url // 闭包捕获
		checkID := generateCheckID()

		p.Go(func() {
			result := c.CheckURL(batchCtx, url, batchID, checkID)
			resultCh <- indexedResult{
				index:  i,
				result: result,
			}
		})
	}

	// 等待并收集结果
	p.Wait()
	close(resultCh)

	// 从通道读取结果
	successCount, failedCount := 0, 0
	for res := range resultCh {
		results[res.index] = res.result
		if res.result.Success {
			successCount++
		} else {
			failedCount++
		}
	}

	// 记录批次摘要
	batchDuration := time.Since(batchStart)
	batchLogger.Info().
		Int("url_count", len(urls)).
		Int("success_count", successCount).
		Int("failed_count", failedCount).
		Dur("batch_duration", batchDuration).
		Dur("avg_latency", batchDuration/time.Duration(len(urls))).
		Msg("批量URL检查完成")

	return results
}

// --- 辅助函数 ---
type indexedResult struct {
	index  int
	result CheckResult
}

func extractHost(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "invalid"
	}
	return u.Hostname()
}

func extractErrorType(err error) string {
	// 简化实现，实际可根据错误字符串判断
	errStr := err.Error()
	switch {
	case contains(errStr, "timeout"):
		return "timeout"
	case contains(errStr, "connection refused"):
		return "connection_refused"
	case contains(errStr, "no such host"):
		return "dns_error"
	default:
		return "unknown"
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr))
}

func generateBatchID() string {
	return "batch_" + uuid.New().String()[:8]
}

func generateCheckID() string {
	return "check_" + uuid.New().String()[:8]
}

// --- 其他方法（Shutdown, GetMetrics等保持类似结构，但使用增强的Metrics） ---
func (c *Checker) Shutdown() error {
	c.logger.Info().
		Int64("total_checks", c.metrics.TotalChecks).
		Int64("failed_checks", c.metrics.FailedChecks).
		Int("active_jobs", c.activeJobs).
		Msg("检查器正在关闭")

	// 清理资源
	if c.sslChecker != nil {
		// 如果有需要清理的SSL检查器资源
	}

	c.logger.Info().Msg("检查器已关闭")
	return nil
}

func (c *Checker) GetMetrics() EnhancedMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 返回副本
	return *c.metrics
}
