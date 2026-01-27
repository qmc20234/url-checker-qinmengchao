package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"time"
	"url-checker/internal/config"

	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/sourcegraph/conc/pool"
)

// --- 优化1: 职责分离的配置结构 ---
type HTTPConfig struct {
	Timeout             time.Duration
	MaxRetries          int
	RetryInterval       time.Duration
	MaxRedirects        int
	UserAgent           string
	AllowInsecure       bool
	FollowRedirect      bool
	TLSHandshakeTimeout time.Duration
	MaxIdleConnsPerHost int
	IdleConnTimeout     time.Duration
}

type PoolConfig struct {
	MaxConcurrent int
	BatchTimeout  time.Duration // 整个批次的超时
}

type SSLConfig struct {
	Enabled            bool
	InsecureSkipVerify bool
	Timeout            time.Duration
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
	if c.SSL.Enabled && c.SSL.Timeout <= 0 {
		return fmt.Errorf("SSL.Timeout must be > 0 when SSL enabled")
	}
	return nil
}

// --- 优化2: HTTP客户端工厂（提高可测试性） ---
type HTTPClientFactory struct {
	config HTTPConfig
}

func NewHTTPClientFactory(config HTTPConfig) *HTTPClientFactory {
	return &HTTPClientFactory{config: config}
}

// 延迟在 [0, base_delay * 2^attempt) 之间随机
func fullJitter(baseDelay time.Duration, attempt int) time.Duration {
	maxDelay := baseDelay * (1 << uint(attempt))
	// 生成0到maxDelay之间的随机延迟
	return time.Duration(rand.Int63n(int64(maxDelay)))
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

		// 使用 fullJitter 计算延迟
		delay := fullJitter(
			100*time.Millisecond, // 基础延迟
			attempt,              // 当前尝试次数
		)

		// 记录重试信息（如果有日志上下文）
		if ctx := r.Request.Context(); ctx != nil {
			if logger, ok := ctx.Value("logger").(zerolog.Logger); ok {
				logger.Debug().
					Int("attempt", attempt).
					Dur("delay", delay).
					Str("url", r.Request.URL).
					Msg("重试延迟计算")
			}
		}

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
	mu         sync.RWMutex
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

// --- 优化4: 重构的检查器构造函数 ---
func NewChecker(checkerConfig config.CheckerConfig, sslConfig config.SSLConfig, logger zerolog.Logger) (*Checker, error) {
	// 创建内部配置结构
	internalConfig := CheckerConfig{
		HTTP: HTTPConfig{
			Timeout:             checkerConfig.Timeout,
			MaxRetries:          checkerConfig.MaxRetries,
			RetryInterval:       checkerConfig.RetryInterval,
			MaxRedirects:        checkerConfig.MaxRedirects,
			UserAgent:           checkerConfig.UserAgent,
			AllowInsecure:       checkerConfig.AllowInsecure,
			FollowRedirect:      checkerConfig.FollowRedirect,
			TLSHandshakeTimeout: checkerConfig.TLSHandshakeTimeout,
			MaxIdleConnsPerHost: checkerConfig.MaxIdleConnsPerHost,
			IdleConnTimeout:     checkerConfig.IdleConnTimeout,
		},
		Pool: PoolConfig{
			MaxConcurrent: checkerConfig.MaxConcurrent,
			BatchTimeout:  checkerConfig.BatchTimeout,
		},
		SSL: SSLConfig{
			Enabled:            sslConfig.Enabled,
			InsecureSkipVerify: sslConfig.InsecureSkipVerify,
			Timeout:            sslConfig.Timeout,
		},
	}

	// 配置验证
	if err := internalConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid checker config: %w", err)
	}

	// 创建HTTP客户端
	clientFactory := NewHTTPClientFactory(internalConfig.HTTP)
	client := clientFactory.Create()

	// 创建SSL检查器（如果启用）
	var sslChecker *SSLChecker
	if internalConfig.SSL.Enabled {
		var err error
		sslChecker, err = NewSSLChecker(internalConfig.SSL, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create SSL checker: %w", err)
		}
	}

	c := &Checker{
		client:     client,
		sslChecker: sslChecker,
		config:     internalConfig,
		logger:     logger.With().Str("component", "checker").Logger(),
	}

	c.logger.Info().
		Int("max_concurrent", internalConfig.Pool.MaxConcurrent).
		Dur("http_timeout", internalConfig.HTTP.Timeout).
		Bool("ssl_enabled", internalConfig.SSL.Enabled).
		Msg("URL检查器初始化完成")

	return c, nil
}

// --- 优化5: 增强的单个URL检查（支持完整追踪） ---
func (c *Checker) CheckURL(ctx context.Context, urlStr string, batchID, checkID string) CheckResult {
	// 开始检查
	start := time.Now()
	host := extractHost(urlStr)

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

	if err != nil {
		// 失败处理
		c.mu.Lock()
		errorType := extractErrorType(err)
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

// IsSSLRequired 判断URL是否需要SSL检查
func IsSSLRequired(urlStr string) (bool, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false, fmt.Errorf("解析URL失败: %w", err)
	}
	return u.Scheme == "https", nil
}

// --- 其他方法（Shutdown, GetMetrics等保持类似结构，但使用增强的Metrics） ---
func (c *Checker) Shutdown() error {
	c.logger.Info().
		Msg("检查器正在关闭")

	// 清理资源
	if c.sslChecker != nil {
		// SSL检查器可能没有需要特殊清理的资源，但如果有，可以在这里调用
	}

	c.logger.Info().Msg("检查器已关闭")
	return nil
}
