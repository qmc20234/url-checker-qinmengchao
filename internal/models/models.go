package models

import "time"

// URL检查请求
type CheckRequest struct {
	URLs []string `json:"urls" binding:"required,min=1,max=100"`
}

// URL检查结果
type CheckResult struct {
	URL        string        `json:"url"`
	StatusCode int           `json:"status_code"`
	Latency    time.Duration `json:"latency_ms"`
	CertExpiry *time.Time    `json:"cert_expiry,omitempty"`
	DaysLeft   int           `json:"days_left,omitempty"`
	Success    bool          `json:"success"`
	Error      string        `json:"error,omitempty"`
	Timestamp  time.Time     `json:"timestamp"`
}

// 批量检查响应
type BatchResponse struct {
	TaskID   string        `json:"task_id"`
	Status   string        `json:"status"`
	Results  []CheckResult `json:"results"`
	Total    int           `json:"total"`
	Duration string        `json:"duration"`
}
