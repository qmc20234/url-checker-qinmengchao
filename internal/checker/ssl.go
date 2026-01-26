package checker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// --- 优化1: 完整的配置结构 ---
type SSLConfig struct {
	// 连接和握手超时
	Timeout time.Duration
	// 是否跳过证书验证（仅获取证书信息）
	InsecureSkipVerify bool
	// 支持的TLS最小版本
	MinTLSVersion uint16
	// 是否验证完整的证书链
	VerifyCertificateChain bool
	// 自定义CA证书池（可选）
	RootCAs *x509.CertPool
	// 服务器名称指示（SNI）
	ServerName string
}

// DefaultSSLConfig 返回默认配置
func DefaultSSLConfig() SSLConfig {
	return SSLConfig{
		Timeout:                10 * time.Second,
		InsecureSkipVerify:     true, // 默认只获取证书，不验证
		MinTLSVersion:          tls.VersionTLS12,
		VerifyCertificateChain: false,
		RootCAs:                nil,
		ServerName:             "",
	}
}

// Validate 验证配置的有效性
func (cfg *SSLConfig) Validate() error {
	if cfg.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if cfg.MinTLSVersion != tls.VersionTLS12 &&
		cfg.MinTLSVersion != tls.VersionTLS13 {
		return fmt.Errorf("unsupported TLS version: %d", cfg.MinTLSVersion)
	}
	return nil
}

// --- 优化2: 增强的结构体和接口 ---
type SSLChecker struct {
	config SSLConfig
	logger zerolog.Logger
}

// NewSSLChecker 创建SSL检查器
func NewSSLChecker(config SSLConfig, logger zerolog.Logger) (*SSLChecker, error) {
	// 验证配置
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid SSL config: %w", err)
	}

	return &SSLChecker{
		config: config,
		logger: logger.With().Str("component", "ssl_checker").Logger(),
	}, nil
}

// CertInfo 证书信息（增强版）
type CertInfo struct {
	URL          string    `json:"url"`
	Host         string    `json:"host"`
	Port         string    `json:"port"`
	Expiry       time.Time `json:"expiry"`
	DaysLeft     int       `json:"days_left"`
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	IsValid      bool      `json:"is_valid"`      // 证书是否有效（未过期）
	IsExpired    bool      `json:"is_expired"`    // 是否已过期
	IsExpiring   bool      `json:"is_expiring"`   // 是否即将过期（30天内）
	IssuedDate   time.Time `json:"issued_date"`   // 颁发日期
	SerialNumber string    `json:"serial_number"` // 序列号
	DNSNames     []string  `json:"dns_names"`     // SAN中的DNS名称
}

// Check 检查SSL证书（优化后）
func (s *SSLChecker) Check(ctx context.Context, urlStr string) (*CertInfo, error) {
	// 为本次检查创建带有请求ID的子Logger
	checkLogger := s.logger.With().
		Str("operation", "ssl_check").
		Str("target_url", urlStr).
		Logger()

	checkLogger.Debug().Msg("开始SSL证书检查")

	// 1. 解析URL
	u, err := url.Parse(urlStr)
	if err != nil {
		checkLogger.Error().
			Err(err).
			Str("raw_url", urlStr).
			Msg("URL解析失败")
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// 2. 提取主机和端口
	host := u.Hostname()
	if host == "" {
		err := fmt.Errorf("URL has no hostname")
		checkLogger.Error().Err(err).Msg("URL缺少主机名")
		return nil, err
	}

	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			err := fmt.Errorf("unsupported scheme: %s", u.Scheme)
			checkLogger.Error().Err(err).Msg("不支持的协议")
			return nil, err
		}
	}

	// 记录连接信息
	checkLogger = checkLogger.With().
		Str("host", host).
		Str("port", port).
		Str("scheme", u.Scheme).
		Logger()

	checkLogger.Debug().
		Dur("timeout", s.config.Timeout).
		Bool("insecure_skip_verify", s.config.InsecureSkipVerify).
		Msg("准备建立TLS连接")

	// 3. 创建带超时的上下文
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	// 4. 配置TLS连接
	tlsConfig := &tls.Config{
		InsecureSkipVerify: s.config.InsecureSkipVerify,
		MinVersion:         s.config.MinTLSVersion,
		RootCAs:            s.config.RootCAs,
	}

	// 设置ServerName（优先使用配置，否则使用主机名）
	if s.config.ServerName != "" {
		tlsConfig.ServerName = s.config.ServerName
	} else {
		tlsConfig.ServerName = host
	}

	// 5. 建立TLS连接
	dialStart := time.Now()
	address := fmt.Sprintf("%s:%s", host, port)

	dialer := &tls.Dialer{
		Config: tlsConfig,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		checkLogger.Error().
			Err(err).
			Str("address", address).
			Dur("dial_duration", time.Since(dialStart)).
			Msg("TLS连接失败")
		return nil, fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	defer conn.Close()

	connectDuration := time.Since(dialStart)
	checkLogger.Debug().
		Dur("connect_duration", connectDuration).
		Msg("TLS连接成功")

	// 6. 获取证书信息
	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		err := fmt.Errorf("no certificates found")
		checkLogger.Error().Err(err).Msg("未找到证书")
		return nil, err
	}

	// 7. 解析服务器证书
	cert := state.PeerCertificates[0]
	checkLogger.Debug().
		Str("cert_subject", cert.Subject.CommonName).
		Str("cert_issuer", cert.Issuer.CommonName).
		Time("cert_not_before", cert.NotBefore).
		Time("cert_not_after", cert.NotAfter).
		Msg("获取到服务器证书")

	// 8. 验证证书链（如果配置要求）
	if s.config.VerifyCertificateChain && !s.config.InsecureSkipVerify {
		opts := x509.VerifyOptions{
			Roots:       s.config.RootCAs,
			CurrentTime: time.Now(),
			DNSName:     tlsConfig.ServerName,
		}

		if _, err := cert.Verify(opts); err != nil {
			checkLogger.Warn().
				Err(err).
				Msg("证书链验证失败")
			// 不返回错误，仅记录警告
		}
	}

	// 9. 计算证书状态
	now := time.Now()
	expiry := cert.NotAfter
	daysLeft := int(expiry.Sub(now).Hours() / 24)

	isExpired := now.After(expiry)
	isExpiring := daysLeft <= 30 && daysLeft > 0
	isValid := !isExpired && daysLeft > 0

	// 10. 构建返回结果
	certInfo := &CertInfo{
		URL:          urlStr,
		Host:         host,
		Port:         port,
		Expiry:       expiry,
		DaysLeft:     daysLeft,
		Issuer:       cert.Issuer.CommonName,
		Subject:      cert.Subject.CommonName,
		IsValid:      isValid,
		IsExpired:    isExpired,
		IsExpiring:   isExpiring,
		IssuedDate:   cert.NotBefore,
		SerialNumber: cert.SerialNumber.String(),
		DNSNames:     cert.DNSNames,
	}

	// 11. 记录检查结果
	logEvent := checkLogger.Info()
	if isExpired {
		logEvent = checkLogger.Error()
	} else if isExpiring {
		logEvent = checkLogger.Warn()
	}

	logEvent.
		Time("certificate_expiry", expiry).
		Int("days_until_expiry", daysLeft).
		Bool("certificate_expired", isExpired).
		Bool("certificate_expiring_soon", isExpiring).
		Strs("certificate_dns_names", cert.DNSNames).
		Msg("SSL证书检查完成")

	return certInfo, nil
}

// --- 优化3: 增强的工具函数 ---

// IsSSLRequired 判断URL是否需要SSL检查（增强版）
func IsSSLRequired(urlStr string) (bool, error) {
	if urlStr == "" {
		return false, fmt.Errorf("empty URL")
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return false, fmt.Errorf("invalid URL: %w", err)
	}

	// 检查scheme（不区分大小写）
	scheme := strings.ToLower(u.Scheme)
	return scheme == "https", nil
}

// CheckWithRetry 带重试的检查（可选功能）
func (s *SSLChecker) CheckWithRetry(ctx context.Context, urlStr string, maxRetries int) (*CertInfo, error) {
	logger := s.logger.With().
		Str("operation", "ssl_check_with_retry").
		Str("target_url", urlStr).
		Int("max_retries", maxRetries).
		Logger()

	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		logger.Debug().Int("attempt", i+1).Msg("尝试SSL检查")

		certInfo, err := s.Check(ctx, urlStr)
		if err == nil {
			if i > 0 {
				logger.Info().Int("attempts", i+1).Msg("SSL检查在重试后成功")
			}
			return certInfo, nil
		}

		lastErr = err
		logger.Warn().
			Err(err).
			Int("attempt", i+1).
			Msg("SSL检查失败")

		// 不是最后一次尝试，则等待后重试
		if i < maxRetries {
			waitTime := time.Duration(i+1) * time.Second
			logger.Debug().Dur("wait_time", waitTime).Msg("等待后重试")

			select {
			case <-time.After(waitTime):
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	logger.Error().
		Err(lastErr).
		Int("total_attempts", maxRetries+1).
		Msg("SSL检查重试多次后仍失败")
	return nil, fmt.Errorf("SSL检查失败，已重试%d次: %w", maxRetries, lastErr)
}
