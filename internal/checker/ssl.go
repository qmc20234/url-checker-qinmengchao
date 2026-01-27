package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/rs/zerolog"
)

// SSLChecker SSL证书检查器
type SSLChecker struct {
	config SSLConfig
	logger zerolog.Logger
}

// CertInfo SSL证书信息
type CertInfo struct {
	Expiry   time.Time
	DaysLeft int
	Valid    bool
}

// NewSSLChecker 创建SSL检查器
func NewSSLChecker(config SSLConfig, logger zerolog.Logger) (*SSLChecker, error) {
	return &SSLChecker{
		config: config,
		logger: logger.With().Str("component", "ssl-checker").Logger(),
	}, nil
}

// Check 检查SSL证书
func (s *SSLChecker) Check(ctx context.Context, urlStr string) (*CertInfo, error) {
	u, err := parseURL(urlStr)
	if err != nil {
		return nil, fmt.Errorf("解析URL失败: %w", err)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}

	// 设置超时
	dialer := &net.Dialer{
		Timeout: s.config.Timeout,
	}

	// TLS配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: s.config.InsecureSkipVerify,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("建立TLS连接失败: %w", err)
	}
	defer conn.Close()

	// 检查证书
	cert := conn.ConnectionState().PeerCertificates[0]
	now := time.Now()
	expiry := cert.NotAfter
	daysLeft := int(expiry.Sub(now).Hours() / 24)

	certInfo := &CertInfo{
		Expiry:   expiry,
		DaysLeft: daysLeft,
		Valid:    now.Before(expiry),
	}

	return certInfo, nil
}

// parseURL 解析URL，提取主机名和端口
func parseURL(urlStr string) (*url.URL, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("解析URL失败: %w", err)
	}

	// 确保URL有Scheme
	if u.Scheme == "" {
		return nil, fmt.Errorf("URL缺少协议方案")
	}

	return u, nil
}
