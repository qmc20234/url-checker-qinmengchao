// tests/integration/sse_parser.go
package integration

import (
	"bufio"
	"io"
	"strings"
)

// SSEMessage SSE消息结构
type SSEMessage struct {
	Event string
	Data  string
}

// CheckResult 检查结果
type CheckResult struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	LatencyMS  int64  `json:"latency_ms"`
	CertExpiry string `json:"cert_expiry,omitempty"`
	DaysLeft   int    `json:"days_left,omitempty"`
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
	Timestamp  string `json:"timestamp"`
}

// EndMessage 结束消息
type EndMessage struct {
	Message string `json:"message"`
}

// ParseSSE 解析SSE响应
func ParseSSE(r io.Reader) ([]SSEMessage, error) {
	scanner := bufio.NewScanner(r)
	var messages []SSEMessage
	var currentMessage SSEMessage

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// 空行表示消息结束
			if currentMessage.Event != "" {
				messages = append(messages, currentMessage)
			}
			currentMessage = SSEMessage{}
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		field := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch field {
		case "event":
			currentMessage.Event = value
		case "data":
			if currentMessage.Data != "" {
				currentMessage.Data += "\n" + value
			} else {
				currentMessage.Data = value
			}
		}
	}

	if currentMessage.Event != "" {
		messages = append(messages, currentMessage)
	}

	return messages, scanner.Err()
}
