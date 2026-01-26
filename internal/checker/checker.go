// internal/checker/checker.go
package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
	"github.com/sourcegraph/conc/pool"

	"url-checker/internal/models"
)

// Config 检查器配置
type Config struct {
	MaxConcurrent  int
	Timeout        time.Duration
	MaxRetries     int
	RetryInterval  time.Duration
	MaxRedirects   int
	UserAgent      string
	AllowInsecure  bool
	FollowRedirect bool
	SSLCheck       bool
	SSLWarnDays    int
}

// Checker URL检查器
type Checker struct {
	client       *resty.Client
	sslChecker   *SSLChecker
	config       Config
	logger       zerolog.Logger
	metrics      *Metrics
	mu           sync.RWMutex
	activeJobs   int
	totalChecks  int64
	failedChecks int64
}

// Metrics 监控指标
type Metrics struct {
	ActiveJobs   int
	TotalChecks  int64
	FailedChecks int64
	AvgLatency   time.Duration
}

// NewChecker 创建检查器（支持依赖注入）
func NewChecker(config Config, logger zerolog.Logger) (*Checker, error) {
	if config.MaxConcurrent <= 0 {
		return nil, fmt.Errorf("max_concurrent must be greater than 0")
	}

	if config.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be greater than 0")
	}

	client := createRestyClient(config)

	c := &Checker{
		client: client,
		sslChecker: &SSLChecker{
			Timeout: 5 * time.Second,
			Logger:  logger,
		},
		config:  config,
		logger:  logger.With().Str("component", "checker").Logger(),
		metrics: &Metrics{},
	}

	c.logger.Info().
		Int("max_concurrent", config.MaxConcurrent).
		Dur("timeout", config.Timeout).
		Int("max_retries", config.MaxRetries).
		Msg("检查器初始化完成")

	return c, nil
}

// createRestyClient 创建Resty客户端
func createRestyClient(config Config) *resty.Client {
	client := resty.New()

	// 基础配置
	client.SetTimeout(config.Timeout)
	client.SetRetryCount(config.MaxRetries)
	client.SetRetryWaitTime(config.RetryInterval)
	client.SetRetryMaxWaitTime(10 * time.Second)

	// 设置User-Agent
	if config.UserAgent != "" {
		client.SetHeader("User-Agent", config.UserAgent)
	}

	// 配置重定向
	if !config.FollowRedirect {
		client.SetRedirectPolicy(resty.NoRedirectPolicy())
	} else if config.MaxRedirects > 0 {
		client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(config.MaxRedirects))
	}

	// 配置HTTP传输层
	transport := &http.Transport{
		TLSHandshakeTimeout: 5 * time.Second,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.AllowInsecure,
		},
	}
	client.SetTransport(transport)

	// 配置指数退避重试策略
	client.SetRetryAfter(func(c *resty.Client, r *resty.Response) (time.Duration, error) {
		attempt := r.Request.Attempt

		// 指数退避算法
		delay := time.Duration(100*(1<<uint(attempt))) * time.Millisecond

		// 最大延迟限制
		if delay > 10*time.Second {
			delay = 10 * time.Second
		}

		// 添加10%的抖动
		jitter := time.Duration(float64(delay) * 0.1)
		delay = delay - jitter + time.Duration(float64(jitter)*2)

		return delay, nil
	})

	return client
}

// CheckURL 检查单个URL
func (c *Checker) CheckURL(ctx context.Context, url string) models.CheckResult {
	c.mu.Lock()
	c.activeJobs++
	c.totalChecks++
	c.metrics.ActiveJobs = c.activeJobs
	c.metrics.TotalChecks = c.totalChecks
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.activeJobs--
		c.metrics.ActiveJobs = c.activeJobs
		c.mu.Unlock()
	}()

	start := time.Now()
	result := models.CheckResult{
		URL:       url,
		Timestamp: time.Now(),
	}

	// 记录开始检查
	c.logger.Debug().
		Str("url", url).
		Msg("开始检查URL")

	// 执行HTTP请求
	resp, err := c.client.R().
		SetContext(ctx).
		SetDoNotParseResponse(true).
		Head(url)

	result.Latency = time.Since(start)

	if err != nil {
		c.mu.Lock()
		c.failedChecks++
		c.metrics.FailedChecks = c.failedChecks
		c.mu.Unlock()

		result.Error = err.Error()
		result.Success = false

		c.logger.Warn().
			Str("url", url).
			Err(err).
			Msg("URL检查失败")

		return result
	}

	defer resp.RawResponse.Body.Close()

	result.StatusCode = resp.StatusCode()
	result.Success = resp.IsSuccess()

	// 记录成功检查
	c.logger.Debug().
		Str("url", url).
		Int("status_code", result.StatusCode).
		Dur("latency", result.Latency).
		Msg("URL检查完成")

	// 如果需要且是HTTPS，检查SSL证书
	if c.config.SSLCheck && IsSSLRequired(url) {
		certInfo, err := c.sslChecker.Check(ctx, url)
		if err == nil {
			result.CertExpiry = &certInfo.Expiry
			result.DaysLeft = certInfo.DaysLeft

			// 检查证书是否即将过期
			if certInfo.DaysLeft <= c.config.SSLWarnDays {
				c.logger.Warn().
					Str("url", url).
					Int("days_left", certInfo.DaysLeft).
					Time("expiry", certInfo.Expiry).
					Msg("SSL证书即将过期")
			}
		} else {
			c.logger.Warn().
				Str("url", url).
				Err(err).
				Msg("SSL证书检查失败")
		}
	}

	return result
}

// BatchCheck 批量检查URL
func (c *Checker) BatchCheck(ctx context.Context, urls []string) []models.CheckResult {
	c.logger.Info().
		Int("url_count", len(urls)).
		Msg("开始批量检查URL")

	batchStart := time.Now()

	// 使用conc的Worker Pool控制并发
	p := pool.New().WithMaxGoroutines(c.config.MaxConcurrent)

	// 准备结果存储
	results := make([]models.CheckResult, len(urls))

	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(ctx, c.timeoutForBatch(len(urls)))
	defer cancel()

	// 使用互斥锁保护结果写入
	var mu sync.Mutex

	for i, url := range urls {
		i, url := i, url // 闭包捕获

		p.Go(func() {
			result := c.CheckURL(ctx, url)

			mu.Lock()
			results[i] = result
			mu.Unlock()
		})
	}

	p.Wait()

	// 记录批量检查完成
	batchDuration := time.Since(batchStart)
	c.logger.Info().
		Int("url_count", len(urls)).
		Dur("duration", batchDuration).
		Msg("批量检查完成")

	return results
}

// timeoutForBatch 计算批量检查的超时时间
func (c *Checker) timeoutForBatch(urlCount int) time.Duration {
	// 基础超时 + 每个URL的预期时间
	baseTimeout := c.config.Timeout
	perURLTimeout := 2 * time.Second

	totalTimeout := baseTimeout + time.Duration(urlCount)*perURLTimeout

	// 限制最大超时时间
	maxTimeout := 5 * time.Minute
	if totalTimeout > maxTimeout {
		return maxTimeout
	}

	return totalTimeout
}

// GetMetrics 获取检查器指标
func (c *Checker) GetMetrics() Metrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return *c.metrics
}

// Shutdown 关闭检查器
func (c *Checker) Shutdown() error {
	c.logger.Info().
		Int64("total_checks", c.totalChecks).
		Int64("failed_checks", c.failedChecks).
		Msg("检查器正在关闭")

	// 如果有需要清理的资源，在这里清理
	// 例如：关闭连接池

	c.logger.Info().Msg("检查器已关闭")
	return nil
}

// SetLogger 设置日志器（可选，用于运行时修改日志级别）
func (c *Checker) SetLogger(logger zerolog.Logger) {
	c.logger = logger.With().Str("component", "checker").Logger()
}
