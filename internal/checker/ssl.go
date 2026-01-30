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
	Expiry   time.Time `json:"expiry"`
	DaysLeft int       `json:"days_left"`
	Valid    bool      `json:"valid"`
	Error    string    `json:"error,omitempty"`
}

// NewSSLChecker 创建SSL检查器
func NewSSLChecker(config SSLConfig, logger zerolog.Logger) (*SSLChecker, error) {
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

	logger.Info().
		Int("days_left", certInfo.DaysLeft).
		Time("expiry", certInfo.Expiry).
		Msg("SSL check completed")

	return certInfo, nil
}

// parseURL 解析URL并进行验证
func (s *SSLChecker) parseURL(urlStr string) (*url.URL, error) {
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

	return &CertInfo{
		Expiry:   expiry,
		DaysLeft: daysLeft,
		Valid:    now.Before(expiry) && now.After(cert.NotBefore),
	}
}
