package checker

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"
	"time"

	"url-checker/internal/models"

	"github.com/go-resty/resty/v2"
	"github.com/sourcegraph/conc/pool"
)

// Checker URL检查器
type Checker struct {
	client        *resty.Client
	sslChecker    *SSLChecker
	maxConcurrent int
	timeout       time.Duration
}

// NewChecker 创建检查器
func NewChecker(maxConcurrent int, timeout time.Duration) *Checker {
	client := resty.New()

	// 配置HTTP客户端
	client.SetTimeout(timeout)
	client.SetRetryCount(3)
	client.SetRetryWaitTime(100 * time.Millisecond)
	client.SetRetryMaxWaitTime(10 * time.Second)

	// 启用HTTP/2，支持SSL
	client.SetTransport(&http.Transport{
		TLSHandshakeTimeout: 5 * time.Second,
		MaxIdleConnsPerHost: 100,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false, // 生产环境应为false
		},
	})

	// 配置重试策略（指数退避）
	client.SetRetryAfter(func(c *resty.Client, r *resty.Response) (time.Duration, error) {
		attempt := r.Request.Attempt

		// 指数退避算法
		delay := time.Duration(100*(1<<uint(attempt))) * time.Millisecond

		// 添加抖动防止惊群
		if delay > 10*time.Second {
			delay = 10 * time.Second
		}

		// 10%的抖动
		jitter := time.Duration(float64(delay) * 0.1)
		delay = delay - jitter + time.Duration(float64(jitter)*2)

		return delay, nil
	})

	return &Checker{
		client:        client,
		sslChecker:    &SSLChecker{Timeout: 5 * time.Second},
		maxConcurrent: maxConcurrent,
		timeout:       timeout,
	}
}

// CheckURL 检查单个URL
func (c *Checker) CheckURL(ctx context.Context, url string) models.CheckResult {
	start := time.Now()
	result := models.CheckResult{
		URL:       url,
		Timestamp: time.Now(),
	}

	// 执行HTTP请求
	resp, err := c.client.R().
		SetContext(ctx).
		SetDoNotParseResponse(true).
		Head(url) // 使用HEAD方法，更快

	result.Latency = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		result.Success = false
		return result
	}

	defer resp.RawResponse.Body.Close()

	result.StatusCode = resp.StatusCode()
	result.Success = resp.IsSuccess()

	// 如果是HTTPS，检查SSL证书
	if IsSSLRequired(url) {
		certInfo, err := c.sslChecker.Check(ctx, url)
		if err == nil {
			result.CertExpiry = &certInfo.Expiry
			result.DaysLeft = certInfo.DaysLeft
		}
	}

	return result
}

// BatchCheck 批量检查URL
func (c *Checker) BatchCheck(ctx context.Context, urls []string) []models.CheckResult {
	// 使用conc的Worker Pool控制并发
	p := pool.New().WithMaxGoroutines(c.maxConcurrent)

	// 准备结果存储
	results := make([]models.CheckResult, len(urls))

	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(ctx, c.timeout*time.Duration(len(urls)))
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
	return results
}
