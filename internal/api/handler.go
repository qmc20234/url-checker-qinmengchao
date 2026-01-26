package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"url-checker/internal/checker"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
)

// Handler HTTP请求处理器
type Handler struct {
	checker *checker.Checker
	logger  zerolog.Logger
}

// NewHandler 创建处理器
func NewHandler(checker *checker.Checker, logger zerolog.Logger) *Handler {
	return &Handler{
		checker: checker,
		logger:  logger}
}

// HealthCheck 健康检查
func (h *Handler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
	})
}

// CheckRequest 检查请求参数
type CheckRequest struct {
	URLs []string `form:"urls" binding:"required,min=1,max=100,dive,required,url"`
}

// CheckStream 流式检查URL
func (h *Handler) CheckStream(c *gin.Context) {
	// 绑定并验证参数
	var req CheckRequest

	// 使用 ShouldBindQuery 绑定查询参数
	if err := c.ShouldBindQuery(&req); err != nil {
		// 获取具体的验证错误信息
		if validationErrors, ok := err.(validator.ValidationErrors); ok {
			errorMessages := make([]string, 0)
			for _, fieldErr := range validationErrors {
				switch fieldErr.Tag() {
				case "required":
					errorMessages = append(errorMessages, "缺少urls参数")
				case "min":
					errorMessages = append(errorMessages, "URL列表不能为空")
				case "max":
					errorMessages = append(errorMessages, "最多支持100个URL")
				case "url":
					errorMessages = append(errorMessages, fmt.Sprintf("无效的URL格式: %s", fieldErr.Value()))
				case "dive":
					// 不做处理，具体错误由子验证器处理
				default:
					errorMessages = append(errorMessages, fieldErr.Error())
				}
			}

			if len(errorMessages) > 0 {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": strings.Join(errorMessages, "; "),
				})
				return
			}
		}

		// 其他错误
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 将可能的逗号分隔项展开为独立的 URL 列表
	expanded := make([]string, 0, len(req.URLs))
	for _, s := range req.URLs {
		for _, part := range strings.Split(s, ",") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			expanded = append(expanded, p)
		}
	}

	req.URLs = expanded

	// 可选：再次检查数量限制
	if len(req.URLs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL列表不能为空"})
		return
	}
	if len(req.URLs) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "最多支持100个URL"})
		return
	}

	// 手动验证URL格式（Gin的url验证可能不够严格）
	for _, urlStr := range req.URLs {
		if !isValidURL(urlStr) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("无效的URL格式: %s", urlStr),
			})
			return
		}
	}

	// 设置SSE响应头
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no") // 禁用nginx缓冲

	// 获取上下文
	ctx := c.Request.Context()

	// 获取结果流
	resultChan := h.checker.BatchCheck(ctx, req.URLs)

	// 流式发送
	for _, result := range resultChan {
		c.SSEvent("check", result)
		c.Writer.Flush()

		// 检查连接是否断开（Gin的方法）
		if c.Writer.Status() == 0 || c.IsAborted() {
			h.logger.Debug().Msg("客户端断开连接")
			return
		}
	}

	// 发送结束事件
	c.SSEvent("end", gin.H{"message": "检查完成"})
	c.Writer.Flush()
}

// isValidURL 更严格的URL验证
func isValidURL(urlStr string) bool {
	// 快速检查
	if urlStr == "" {
		return false
	}

	// 必须有http或https协议
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		return false
	}

	// 解析URL
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// 检查协议
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	// 检查主机名
	if u.Host == "" {
		return false
	}

	// 可选：检查主机名格式
	if strings.Contains(u.Host, "..") || strings.HasPrefix(u.Host, ".") || strings.HasSuffix(u.Host, ".") {
		return false
	}

	// 可选：限制URL长度
	if len(urlStr) > 2000 {
		return false
	}

	return true
}

// 生成任务ID（简单实现）
func generateTaskID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(6)
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}
