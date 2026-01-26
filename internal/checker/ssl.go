package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"time"

	"github.com/rs/zerolog"
)

// SSLChecker SSL证书检查器
type SSLChecker struct {
	Timeout time.Duration
	Logger  zerolog.Logger
}

// CertInfo 证书信息
type CertInfo struct {
	Expiry   time.Time
	DaysLeft int
	Issuer   string
	Subject  string
}

// Check 检查SSL证书
func (s *SSLChecker) Check(ctx context.Context, urlStr string) (*CertInfo, error) {
	// 解析URL，提取主机和端口
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// 获取主机名和端口
	host := u.Hostname()
	port := u.Port()

	// 如果没有指定端口，根据协议使用默认端口
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else if u.Scheme == "http" {
			port = "80"
		} else {
			return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
		}
	}

	// 验证主机名
	if host == "" {
		return nil, fmt.Errorf("URL has no hostname")
	}

	fmt.Printf("[SSLChecker] 检查SSL: 主机=%s, 端口=%s\n", host, port)

	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	// 建立TLS连接
	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: true, // 仅获取证书，不验证
		},
	}

	address := fmt.Sprintf("%s:%s", host, port)
	fmt.Printf("[SSLChecker] 连接地址: %s\n", address)

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s:%s: %w", host, port, err)
	}
	defer conn.Close()

	// 获取证书
	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	// 获取服务器证书
	cert := state.PeerCertificates[0]

	// 计算剩余天数
	now := time.Now()
	expiry := cert.NotAfter
	daysLeft := int(expiry.Sub(now).Hours() / 24)

	return &CertInfo{
		Expiry:   expiry,
		DaysLeft: daysLeft,
		Issuer:   cert.Issuer.CommonName,
		Subject:  cert.Subject.CommonName,
	}, nil
}

// IsSSLRequired 判断URL是否需要SSL检查
func IsSSLRequired(url string) bool {
	return len(url) > 8 && url[:8] == "https://"
}
