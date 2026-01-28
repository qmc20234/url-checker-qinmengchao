package checker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

var (
	ErrInvalidURL         = errors.New("invalid URL format")
	ErrUnsupportedScheme  = errors.New("unsupported URL scheme")
	ErrConnectionFailed   = errors.New("connection failed")
	ErrTLSError           = errors.New("TLS handshake error")
	ErrNoCertificate      = errors.New("no certificate found")
	ErrCertificateExpired = errors.New("certificate expired")
)

// SSLChecker SSL证书检查器
type SSLChecker struct {
	config SSLConfig
	logger zerolog.Logger
	client *http.Client // 可选的HTTP客户端，用于复用连接
}

// CertInfo SSL证书信息
type CertInfo struct {
	Expiry     time.Time `json:"expiry"`
	DaysLeft   int       `json:"days_left"`
	Valid      bool      `json:"valid"`
	Issuer     string    `json:"issuer"`
	CommonName string    `json:"common_name"`
	AltNames   []string  `json:"alt_names"`
	Error      string    `json:"error,omitempty"`
	IsWarning  bool      `json:"is_warning"` // 即将过期警告
}

// NewSSLChecker 创建SSL检查器
func NewSSLChecker(config SSLConfig, logger zerolog.Logger) (*SSLChecker, error) {
	// 验证配置
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}

	return &SSLChecker{
		config: config,
		logger: logger.With().Str("component", "ssl-checker").Logger(),
	}, nil
}

// Check 检查SSL证书（支持上下文取消和超时）
func (s *SSLChecker) Check(ctx context.Context, urlStr string) (*CertInfo, error) {
	logger := s.logger.With().Str("url", urlStr).Logger()

	// 解析URL
	u, err := s.parseURL(urlStr)
	if err != nil {
		logger.Error().Err(err).Msg("failed to parse URL")
		return &CertInfo{
			Error: err.Error(),
			Valid: false,
		}, fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}

	// 验证协议
	if !strings.EqualFold(u.Scheme, "https") {
		err := fmt.Errorf("%w: %s", ErrUnsupportedScheme, u.Scheme)
		logger.Warn().Err(err).Msg("unsupported scheme")
		return &CertInfo{
			Error: err.Error(),
			Valid: false,
		}, err
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}

	target := net.JoinHostPort(host, port)
	logger.Debug().Str("target", target).Msg("starting SSL check")

	// 创建带有取消功能的连接器
	dialer := &net.Dialer{
		Timeout:   s.config.Timeout,
		KeepAlive: -1, // 禁用keep-alive，因为我们只需要一次连接
	}

	// TLS配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: s.config.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12, // 设置最低TLS版本
		ServerName:         host,             // SNI支持
	}

	// 建立TCP连接
	rawConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		logger.Error().Err(err).Msg("failed to establish TCP connection")
		return &CertInfo{
			Error: err.Error(),
			Valid: false,
		}, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	// 确保TCP连接在函数结束时关闭
	defer func() {
		if rawConn != nil {
			rawConn.Close()
		}
	}()

	// 创建TLS连接
	conn := tls.Client(rawConn, tlsConfig)

	// 设置TLS握手超时
	handshakeCtx, handshakeCancel := context.WithTimeout(ctx, s.config.Timeout)
	defer handshakeCancel()

	// 执行TLS握手（带超时控制）
	handshakeDone := make(chan error, 1)
	go func() {
		handshakeDone <- conn.Handshake()
	}()

	select {
	case <-handshakeCtx.Done():
		logger.Error().Err(handshakeCtx.Err()).Msg("TLS handshake timeout")
		return &CertInfo{
			Error: "TLS handshake timeout",
			Valid: false,
		}, ErrTLSError
	case err := <-handshakeDone:
		if err != nil {
			logger.Error().Err(err).Msg("TLS handshake failed")
			return &CertInfo{
				Error: err.Error(),
				Valid: false,
			}, fmt.Errorf("%w: %v", ErrTLSError, err)
		}
	}

	// 验证证书链
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		logger.Error().Msg("no certificate found")
		return &CertInfo{
			Error: "no certificate presented by server",
			Valid: false,
		}, ErrNoCertificate
	}

	// 获取服务器证书（第一个证书）
	cert := state.PeerCertificates[0]
	certInfo := s.extractCertInfo(cert)

	// 检查证书有效性
	if !certInfo.Valid {
		logger.Warn().Time("expiry", certInfo.Expiry).Msg("certificate expired")
		return certInfo, ErrCertificateExpired
	}

	// 检查证书是否即将过期（例如30天内）
	if certInfo.DaysLeft <= 30 {
		certInfo.IsWarning = true
		logger.Warn().
			Int("days_left", certInfo.DaysLeft).
			Time("expiry", certInfo.Expiry).
			Msg("certificate will expire soon")
	}

	logger.Info().
		Int("days_left", certInfo.DaysLeft).
		Time("expiry", certInfo.Expiry).
		Bool("valid", certInfo.Valid).
		Msg("SSL check completed")

	return certInfo, nil
}

// CheckWithRetry 带重试机制的检查
func (s *SSLChecker) CheckWithRetry(ctx context.Context, urlStr string, maxRetries int) (*CertInfo, error) {
	var lastErr error
	var certInfo *CertInfo

	for i := 0; i <= maxRetries; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if i > 0 {
			// 指数退避
			backoff := time.Duration(1<<uint(i-1)) * time.Second
			time.Sleep(backoff)
			s.logger.Debug().Int("retry", i).Dur("backoff", backoff).Msg("retrying SSL check")
		}

		certInfo, lastErr = s.Check(ctx, urlStr)
		if lastErr == nil {
			return certInfo, nil
		}

		// 如果是证书过期错误，不重试
		if errors.Is(lastErr, ErrCertificateExpired) {
			return certInfo, lastErr
		}

		s.logger.Warn().Err(lastErr).Int("attempt", i+1).Msg("SSL check failed")
	}

	return certInfo, fmt.Errorf("failed after %d attempts: %w", maxRetries+1, lastErr)
}

// parseURL 解析URL并进行验证
func (s *SSLChecker) parseURL(urlStr string) (*url.URL, error) {
	// 如果URL没有协议前缀，添加https://
	if !strings.Contains(urlStr, "://") {
		urlStr = "https://" + urlStr
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	// 验证必要部分
	if u.Host == "" {
		return nil, errors.New("missing host in URL")
	}

	return u, nil
}

// extractCertInfo 从证书中提取信息
func (s *SSLChecker) extractCertInfo(cert *x509.Certificate) *CertInfo {
	now := time.Now()
	expiry := cert.NotAfter
	daysLeft := int(expiry.Sub(now).Hours() / 24)

	// 提取主题备用名称
	var altNames []string
	altNames = append(altNames, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		altNames = append(altNames, ip.String())
	}
	for _, email := range cert.EmailAddresses {
		altNames = append(altNames, email)
	}

	return &CertInfo{
		Expiry:     expiry,
		DaysLeft:   daysLeft,
		Valid:      now.Before(expiry) && now.After(cert.NotBefore),
		Issuer:     cert.Issuer.CommonName,
		CommonName: cert.Subject.CommonName,
		AltNames:   altNames,
	}
}

// BatchCheck 批量检查多个URL的SSL证书
func (s *SSLChecker) BatchCheck(ctx context.Context, urls []string) (map[string]*CertInfo, []error) {
	results := make(map[string]*CertInfo)
	var errors []error

	// 使用工作池限制并发
	maxConcurrency := 10
	semaphore := make(chan struct{}, maxConcurrency)
	resultChan := make(chan struct {
		url  string
		info *CertInfo
		err  error
	}, len(urls))

	// 启动goroutine处理每个URL
	for _, urlStr := range urls {
		go func(u string) {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			info, err := s.Check(ctx, u)
			resultChan <- struct {
				url  string
				info *CertInfo
				err  error
			}{u, info, err}
		}(urlStr)
	}

	// 收集结果
	for i := 0; i < len(urls); i++ {
		select {
		case <-ctx.Done():
			errors = append(errors, ctx.Err())
			return results, errors
		case result := <-resultChan:
			if result.err != nil {
				errors = append(errors, fmt.Errorf("%s: %w", result.url, result.err))
			} else {
				results[result.url] = result.info
			}
		}
	}

	return results, errors
}
