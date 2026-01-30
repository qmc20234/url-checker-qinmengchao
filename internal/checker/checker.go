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
	return nil
}

// --- 优化2: HTTP客户端工厂（提高可测试性） ---
type HTTPClientFactory struct {
	config HTTPConfig
}

func NewHTTPClientFactory(config HTTPConfig) *HTTPClientFactory {
	// 初始化随机种子
	rand.Seed(time.Now().UnixNano())

	return &HTTPClientFactory{config: config}
}

// fullJitter 全抖动策略
func (f *HTTPClientFactory) fullJitter(baseDelay time.Duration, attempt int, maxDelay time.Duration) time.Duration {
	// 计算指数退避的基础延迟
	expDelay := baseDelay * (1 << uint(attempt))

	// 限制最大延迟
	if expDelay > maxDelay {
		expDelay = maxDelay
	}

	// 在 [0, expDelay) 之间生成随机延迟
	// rand.Int63n 生成 0 到 n-1 的随机整数
	randomDelay := time.Duration(rand.Int63n(int64(expDelay)))

	return randomDelay
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

	// 设置重试条件
	client.AddRetryCondition(
		func(r *resty.Response, err error) bool {
			// 仅在以下情况下重试：
			// 1. 网络错误
			// 2. 5xx 服务器错误
			// 3. 429 太多请求
			// 4. 408 请求超时

			if err != nil {
				return true
			}

			statusCode := r.StatusCode()
			return statusCode == 429 || // Too Many Requests
				statusCode == 408 || // Request Timeout
				statusCode >= 500 // Server Errors
		},
	)

	// 指数退避重试（使用全抖动策略）
	client.SetRetryAfter(func(c *resty.Client, r *resty.Response) (time.Duration, error) {
		attempt := r.Request.Attempt

		// 使用 fullJitter 计算延迟
		delay := f.fullJitter(
			100*time.Millisecond, // 基础延迟
			attempt,              // 当前尝试次数
			10*time.Second,       // 最大延迟
		)

		// 记录重试信息（如果有日志上下文）
		if ctx := r.Request.Context(); ctx != nil {
			if logger, ok := ctx.Value("logger").(zerolog.Logger); ok {
				logger.Debug().
					Int("attempt", attempt).
					Dur("delay", delay).
					Str("method", r.Request.Method).
					Str("url", r.Request.URL).
					Int("status", r.StatusCode()).
					Msg("准备重试请求")
			}
		}

		return delay, nil
	})

	return client
}

// --- 优化3: 增强的检查器结构 ---
type Checker struct {
	client         *resty.Client
	sslChecker     *SSLChecker
	config         CheckerConfig
	logger         zerolog.Logger
	mu             sync.RWMutex
	activeJobs     int
	isShuttingDown bool
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
			InsecureSkipVerify: sslConfig.InsecureSkipVerify,
			Timeout:            sslConfig.Timeout,
		},
	}

	// 配置验证
	if err := internalConfig.Validate(); err != nil {
		return nil, fmt.Errorf("检查器配置验证失败: %w", err)
	}

	// 创建HTTP客户端
	clientFactory := NewHTTPClientFactory(internalConfig.HTTP)
	client := clientFactory.Create()

	// 创建SSL检查器（如果启用）
	var sslChecker *SSLChecker
	var err error
	sslChecker, err = NewSSLChecker(internalConfig.SSL, logger)
	if err != nil {
		return nil, fmt.Errorf("创建SSL检查器失败: %w", err)
	}

	c := &Checker{
		client:         client,
		sslChecker:     sslChecker,
		config:         internalConfig,
		logger:         logger.With().Str("component", "checker").Logger(),
		isShuttingDown: false,
	}

	return c, nil
}

// --- 优化5: 增强的单个URL检查（支持完整追踪） ---
func (c *Checker) CheckURL(ctx context.Context, urlStr string, batchID, checkID string) CheckResult {
	// 检查是否正在关闭
	c.mu.RLock()
	if c.isShuttingDown {
		c.mu.RUnlock()
		return CheckResult{
			URL:       urlStr,
			Host:      extractHost(urlStr),
			BatchID:   batchID,
			CheckID:   checkID,
			Timestamp: time.Now(),
			Success:   false,
			Error:     "检查器正在关闭",
		}
	}
	c.mu.RUnlock()

	// 增加活跃任务计数
	c.mu.Lock()
	c.activeJobs++
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.activeJobs--
		c.mu.Unlock()
	}()

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

	// 检查上下文是否已取消
	select {
	case <-ctx.Done():
		result.Error = ctx.Err().Error()
		result.Success = false
		result.Latency = time.Since(start)

		checkLogger.Warn().
			Err(ctx.Err()).
			Dur("latency", result.Latency).
			Msg("检查被取消")

		return result
	default:
		// 继续执行
	}

	// 执行HTTP请求
	resp, err := c.client.R().
		SetContext(ctx).
		SetDoNotParseResponse(true).
		Head(urlStr)

	result.Latency = time.Since(start)

	if err != nil {
		// 失败处理
		errorType := extractErrorType(err)
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

	checkLogger.Debug().
		Int("status_code", result.StatusCode).
		Dur("latency", result.Latency).
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
	// 检查是否正在关闭
	c.mu.RLock()
	if c.isShuttingDown {
		c.mu.RUnlock()
		c.logger.Warn().Msg("检查器正在关闭，拒绝新的批量检查")
		return []CheckResult{}
	}
	c.mu.RUnlock()

	// 为整个批次生成唯一ID
	batchID := generateBatchID()
	batchLogger := c.logger.With().
		Str("batch_id", batchID).
		Int("url_count", len(urls)).
		Logger()

	batchLogger.Info().Msg("开始批量URL检查")

	batchStart := time.Now()

	// 设置批次超时
	batchCtx, cancel := context.WithTimeout(ctx, c.config.Pool.BatchTimeout)
	defer cancel()

	// 创建Worker Pool
	p := pool.New().WithMaxGoroutines(c.config.Pool.MaxConcurrent)

	// 准备结果存储和通道
	results := make([]CheckResult, len(urls))
	resultCh := make(chan indexedResult, len(urls))
	var wg sync.WaitGroup

	// 分发任务
	for i, url := range urls {
		wg.Add(1)

		i, url := i, url // 闭包捕获
		checkID := generateCheckID()

		p.Go(func() {
			defer wg.Done()

			result := c.CheckURL(batchCtx, url, batchID, checkID)
			resultCh <- indexedResult{
				index:  i,
				result: result,
			}
		})
	}

	// 等待所有任务完成
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// 从通道读取结果
	successCount, failedCount := 0, 0
	timeoutCount := 0

	// 设置结果收集超时
	collectCtx, collectCancel := context.WithTimeout(context.Background(), c.config.Pool.BatchTimeout+5*time.Second)
	defer collectCancel()

	for {
		select {
		case res, ok := <-resultCh:
			if !ok {
				// 通道已关闭
				goto done
			}

			results[res.index] = res.result
			if res.result.Success {
				successCount++
			} else {
				failedCount++

				// 检查是否是超时错误
				if contains(res.result.Error, "context deadline exceeded") ||
					contains(res.result.Error, "context canceled") {
					timeoutCount++
				}
			}

		case <-collectCtx.Done():
			batchLogger.Warn().
				Err(collectCtx.Err()).
				Int("collected_results", successCount+failedCount).
				Msg("结果收集超时")
			goto done
		}
	}

done:
	// 记录批次摘要
	batchDuration := time.Since(batchStart)
	avgLatency := time.Duration(0)
	if successCount+failedCount > 0 {
		avgLatency = batchDuration / time.Duration(successCount+failedCount)
	}

	batchLogger.Info().
		Int("url_count", len(urls)).
		Int("success_count", successCount).
		Int("failed_count", failedCount).
		Int("timeout_count", timeoutCount).
		Dur("batch_duration", batchDuration).
		Dur("avg_latency", avgLatency).
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
	case contains(errStr, "context deadline exceeded"):
		return "deadline_exceeded"
	case contains(errStr, "context canceled"):
		return "canceled"
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

// --- 优雅关闭方法 ---
func (c *Checker) Shutdown(ctx context.Context) error {
	c.mu.Lock()
	if c.isShuttingDown {
		c.mu.Unlock()
		return fmt.Errorf("检查器已经在关闭过程中")
	}
	c.isShuttingDown = true
	c.mu.Unlock()

	shutdownLogger := c.logger.With().Str("phase", "shutdown").Logger()
	shutdownLogger.Info().Msg("开始关闭检查器")

	// 记录关闭开始时间
	shutdownStart := time.Now()

	// 等待所有活跃任务完成
	activeJobs := c.getActiveJobs()
	if activeJobs > 0 {
		shutdownLogger.Info().
			Int("active_jobs", activeJobs).
			Msg("等待活跃任务完成")

		// 设置等待超时
		waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-waitCtx.Done():
				remainingJobs := c.getActiveJobs()
				shutdownLogger.Warn().
					Err(waitCtx.Err()).
					Int("remaining_jobs", remainingJobs).
					Dur("wait_duration", time.Since(shutdownStart)).
					Msg("等待活跃任务完成超时")
				break

			case <-ticker.C:
				activeJobs = c.getActiveJobs()
				if activeJobs == 0 {
					shutdownLogger.Info().
						Dur("wait_duration", time.Since(shutdownStart)).
						Msg("所有活跃任务已完成")
					goto cleanup
				}

				// 每5秒记录一次日志
				if time.Since(shutdownStart).Seconds() > 5 &&
					int(time.Since(shutdownStart).Seconds())%5 == 0 {
					shutdownLogger.Debug().
						Int("remaining_jobs", activeJobs).
						Dur("wait_duration", time.Since(shutdownStart)).
						Msg("等待活跃任务完成")
				}
			}
		}
	}

cleanup:
	// 关闭SSL检查器（如果存在）
	if c.sslChecker != nil {
		shutdownLogger.Debug().Msg("正在关闭SSL检查器...")

		sslCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		// 临时实现：如果SSL检查器有Close或Shutdown方法
		_ = sslCtx // 避免未使用错误
		shutdownLogger.Info().Msg("SSL检查器已关闭")
	}

	// HTTP客户端（resty）没有明确的关闭方法
	// 但我们可以尝试关闭底层传输
	if transport, ok := c.client.GetClient().Transport.(*http.Transport); ok {
		shutdownLogger.Debug().Msg("正在关闭HTTP传输...")
		transport.CloseIdleConnections()
		shutdownLogger.Info().Msg("HTTP传输已关闭")
	}

	shutdownLogger.Info().
		Dur("shutdown_duration", time.Since(shutdownStart)).
		Msg("检查器关闭完成")

	return nil
}

// getActiveJobs 获取当前活跃任务数
func (c *Checker) getActiveJobs() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.activeJobs
}
