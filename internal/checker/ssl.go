package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// SSLChecker SSL证书检查器
type SSLChecker struct {
	Timeout time.Duration
}

// CertInfo 证书信息
type CertInfo struct {
	Expiry   time.Time
	DaysLeft int
	Issuer   string
	Subject  string
}

// Check 检查SSL证书
func (s *SSLChecker) Check(ctx context.Context, host string) (*CertInfo, error) {
	// 解析主机和端口
	host, port, err := net.SplitHostPort(host)
	if err != nil {
		// 默认HTTPS端口
		host = host
		port = "443"
	}

	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	// 建立TLS连接
	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: true, // 仅获取证书，不验证
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
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
