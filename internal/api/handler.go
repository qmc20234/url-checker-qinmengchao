package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"url-checker/internal/checker"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
)

// --- 优化1: 配置结构定义 ---
type HandlerConfig struct {
	// 验证错误消息配置
	ValidationMessages map[string]string
	// SSE响应头配置
	SSEHeaders map[string]string
	// 请求超时时间
	RequestTimeout time.Duration
	// 最大并发请求数
	MaxConcurrentRequests int
}

// 默认配置
func DefaultHandlerConfig() HandlerConfig {
	return HandlerConfig{
		ValidationMessages: map[string]string{
			"required": "参数 %s 为必填项",
			"url":      "参数 %s 包含无效的URL格式: %v",
			"min":      "参数 %s 至少需要 %v 个元素",
			"dive":     "参数 %s 中的元素验证失败",
		},
		SSEHeaders: map[string]string{
			"Content-Type":                "text/event-stream",
			"Cache-Control":               "no-cache",
			"Connection":                  "keep-alive",
			"X-Accel-Buffering":           "no",
			"Access-Control-Allow-Origin": "*",
		},
		RequestTimeout:        30 * time.Second,
		MaxConcurrentRequests: 100,
	}
}

// Handler HTTP请求处理器
type Handler struct {
	checker        *checker.Checker
	logger         zerolog.Logger
	config         HandlerConfig
	mu             sync.RWMutex
	activeRequests int
}

// NewHandler 创建处理器（支持自定义配置）
func NewHandler(checker *checker.Checker, logger zerolog.Logger, config HandlerConfig) *Handler {
	cfg := config

	return &Handler{
		checker: checker,
		logger:  logger.With().Str("component", "api-handler").Logger(),
		config:  cfg,
	}
}

// CheckRequest 检查请求参数
type CheckRequest struct {
	URLs []string `form:"urls" binding:"required,min=1,max=100,dive,required,url"`
}

// --- 优化2: 增强的日志上下文工具函数 ---
// 从Gin上下文获取请求专用的Logger
func getRequestLogger(c *gin.Context) zerolog.Logger {
	if logger, exists := c.Get("logger"); exists {
		if l, ok := logger.(zerolog.Logger); ok {
			return l
		}
	}
	return zerolog.Nop()
}

// --- 优化3: 结构化的验证错误处理 ---
func (h *Handler) handleValidationError(c *gin.Context, err error) {
	requestLogger := getRequestLogger(c)

	// 记录验证失败的详细上下文
	validationLog := requestLogger.Error().Err(err)

	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		errorDetails := make([]string, 0, len(validationErrors))

		for _, fieldErr := range validationErrors {
			// 使用配置化的错误消息
			var msg string
			if template, exists := h.config.ValidationMessages[fieldErr.Tag()]; exists {
				msg = fmt.Sprintf(template, fieldErr.Field(), fieldErr.Value(), fieldErr.Param())
			} else {
				msg = fieldErr.Error()
			}
			errorDetails = append(errorDetails, msg)

			// 为每个验证错误记录结构化信息
			validationLog = validationLog.
				Str(fmt.Sprintf("validation_%s_field", fieldErr.Field()), fieldErr.Tag()).
				Interface(fmt.Sprintf("validation_%s_value", fieldErr.Field()), fieldErr.Value())
		}

		// 记录完整的验证失败日志
		validationLog.
			Strs("validation_errors", errorDetails).
			Str("client_ip", c.ClientIP()).
			Str("request_path", c.Request.URL.Path).
			Msg("请求参数验证失败")

		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "请求参数无效",
			"details": errorDetails,
			"code":    "VALIDATION_ERROR",
		})
	} else {
		// 非验证错误
		requestLogger.Error().
			Err(err).
			Str("error_type", "binding_error").
			Msg("请求参数绑定失败")

		c.JSON(http.StatusBadRequest, gin.H{
			"error": "请求参数格式错误",
			"code":  "BINDING_ERROR",
		})
	}
}

// CheckStream 流式检查URL（优化后）
func (h *Handler) CheckStream(c *gin.Context) {
	// 1. 检查并发请求限制
	if !h.acquireRequestSlot() {
		requestLogger := getRequestLogger(c)
		requestLogger.Warn().
			Int("active_requests", h.getActiveRequests()).
			Int("max_concurrent", h.config.MaxConcurrentRequests).
			Msg("超出并发请求限制")

		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "服务器忙，请稍后重试",
			"code":  "TOO_MANY_REQUESTS",
		})
		return
	}
	defer h.releaseRequestSlot()

	// 2. 获取请求专用的Logger（包含request_id）
	requestLogger := getRequestLogger(c)

	// 3. 添加panic恢复机制
	defer func() {
		if r := recover(); r != nil {
			requestLogger.Error().
				Interface("panic", r).
				Str("stack", getStackTrace()).
				Msg("处理请求时发生panic")

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "服务器内部错误",
				"code":  "INTERNAL_SERVER_ERROR",
			})
		}
	}()

	// 4. 记录请求开始
	requestLogger.Info().
		Str("handler", "CheckStream").
		Str("client_ip", c.ClientIP()).
		Str("user_agent", c.Request.UserAgent()).
		Msg("开始处理URL检查请求")

	// 5. 绑定并验证参数
	var req CheckRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		h.handleValidationError(c, err)
		return
	}

	// 6. 记录验证成功的参数摘要
	requestLogger.Info().
		Int("url_count", len(req.URLs)).
		Str("urls_sample", getURLsSample(req.URLs)). // 避免记录所有URL
		Msg("请求参数验证成功")

	// 7. 设置SSE响应头（使用配置）
	for key, value := range h.config.SSEHeaders {
		c.Header(key, value)
	}

	// 8. 设置请求超时上下文
	ctx := c.Request.Context()
	var cancel context.CancelFunc

	if h.config.RequestTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, h.config.RequestTimeout)
		defer cancel()

		requestLogger.Debug().
			Dur("request_timeout", h.config.RequestTimeout).
			Msg("设置请求超时上下文")
	}

	// 9. 记录批量检查开始
	batchStart := time.Now()
	requestLogger.Info().
		Int("batch_size", len(req.URLs)).
		Msg("开始批量URL检查")

	// 10. 创建批次ID用于追踪
	batchID := generateBatchID()
	batchLogger := requestLogger.With().Str("batch_id", batchID).Logger()

	// 11. 创建连接状态检查通道
	clientClosedChan := make(chan bool, 1)
	go func() {
		// 监听客户端是否断开连接
		<-ctx.Done()
		clientClosedChan <- true
	}()

	// 12. 获取结果流
	resultChan := h.checker.BatchCheck(ctx, req.URLs)

	// 13. 流式发送
	sentCount := 0
	sendErrors := 0

	// 记录发送开始时间
	sendStart := time.Now()

	for _, result := range resultChan {
		// 检查上下文是否已取消（超时或客户端断开）
		select {
		case <-ctx.Done():
			batchLogger.Warn().
				Err(ctx.Err()).
				Int("sent_results", sentCount).
				Dur("send_duration", time.Since(sendStart)).
				Msg("请求上下文已取消，停止发送")
			return
		default:
			// 继续发送
		}

		// 发送SSE事件，捕获发送错误
		if err := sendSSEEvent(c, "check", result, batchLogger); err != nil {
			sendErrors++
			batchLogger.Error().
				Err(err).
				Int("send_errors", sendErrors).
				Str("url", result.URL).
				Msg("发送SSE事件失败")

			// 如果连续发送错误超过阈值，停止发送
			if sendErrors >= 3 {
				batchLogger.Error().
					Int("send_errors", sendErrors).
					Msg("发送错误过多，停止发送")
				return
			}
			continue
		}

		sentCount++

		// 可选：记录每个结果的摘要（避免日志过多）
		if batchLogger.GetLevel() == zerolog.DebugLevel {
			batchLogger.Debug().
				Str("url", result.URL).
				Int("status_code", result.StatusCode).
				Bool("success", result.Success).
				Dur("latency", result.Latency).
				Msg("发送检查结果")
		}

		// 检查连接是否断开
		if c.Writer.Status() == 0 || c.IsAborted() {
			batchLogger.Info().
				Int("sent_results", sentCount).
				Dur("send_duration", time.Since(sendStart)).
				Msg("客户端提前断开连接")
			return
		}
	}

	// 14. 记录批量检查完成
	batchDuration := time.Since(batchStart)
	sendDuration := time.Since(sendStart)

	batchLogger.Info().
		Int("total_urls", len(req.URLs)).
		Int("sent_results", sentCount).
		Int("send_errors", sendErrors).
		Dur("batch_duration", batchDuration).
		Dur("send_duration", sendDuration).
		Msg("批量URL检查完成")

	// 15. 发送结束事件
	if err := sendSSEEvent(c, "end", gin.H{
		"message":  "检查完成",
		"batch_id": batchID,
		"stats": gin.H{
			"total_urls":   len(req.URLs),
			"sent_results": sentCount,
			"errors":       sendErrors,
			"duration_ms":  batchDuration.Milliseconds(),
			"completed_at": time.Now().Format(time.RFC3339),
		},
	}, batchLogger); err != nil {
		batchLogger.Error().
			Err(err).
			Msg("发送结束事件失败")
	}

	// 确保所有数据都已发送
	c.Writer.Flush()
}

// --- 辅助函数 ---

// acquireRequestSlot 获取请求槽位
func (h *Handler) acquireRequestSlot() bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.activeRequests >= h.config.MaxConcurrentRequests {
		return false
	}

	h.activeRequests++
	return true
}

// releaseRequestSlot 释放请求槽位
func (h *Handler) releaseRequestSlot() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.activeRequests > 0 {
		h.activeRequests--
	}
}

// getActiveRequests 获取当前活跃请求数
func (h *Handler) getActiveRequests() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.activeRequests
}

// sendSSEEvent 安全的SSE事件发送
func sendSSEEvent(c *gin.Context, event string, data interface{}, logger zerolog.Logger) error {
	defer func() {
		if r := recover(); r != nil {
			logger.Error().
				Interface("panic", r).
				Str("event", event).
				Msg("发送SSE事件时发生panic")
		}
	}()

	c.SSEvent(event, data)

	c.Writer.Flush()

	// 检查写入是否出错
	if c.Writer.Written() {
		// 已经写入成功
		return nil
	}

	// 检查是否有错误
	if c.Errors != nil && len(c.Errors) > 0 {
		return fmt.Errorf("写入响应时出错: %v", c.Errors.String())
	}

	// 检查Writer是否处于错误状态
	// 注意：http.ResponseWriter没有标准的方法来检查错误
	// 我们可以通过尝试写入一个空字节来测试连接
	return nil
}

// getURLsSample 获取URL样本（避免在日志中记录所有URL）
func getURLsSample(urls []string) string {
	if len(urls) == 0 {
		return ""
	}

	// 只显示前3个URL作为样本
	sampleCount := 3
	if len(urls) < sampleCount {
		sampleCount = len(urls)
	}

	sample := urls[:sampleCount]
	if len(urls) > sampleCount {
		return fmt.Sprintf("%s ... (+%d more)", strings.Join(sample, ", "), len(urls)-sampleCount)
	}
	return strings.Join(sample, ", ")
}

// getStackTrace 获取堆栈跟踪
func getStackTrace() string {
	// 简化的堆栈跟踪实现
	// 实际项目中可以使用 runtime.Callers
	return "stack_trace_placeholder"
}

// generateBatchID 生成批次ID
func generateBatchID() string {
	return fmt.Sprintf("batch_%d", time.Now().UnixNano())
}

// Shutdown 优雅关闭处理器
func (h *Handler) Shutdown(ctx context.Context) error {
	shutdownLogger := h.logger.With().Str("phase", "shutdown").Logger()
	shutdownLogger.Info().Msg("开始关闭API处理器")

	// 等待所有活跃请求完成或超时
	start := time.Now()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			activeRequests := h.getActiveRequests()
			shutdownLogger.Warn().
				Err(ctx.Err()).
				Int("remaining_requests", activeRequests).
				Dur("wait_duration", time.Since(start)).
				Msg("关闭超时，强制终止")
			return fmt.Errorf("API处理器关闭超时，仍有 %d 个活跃请求", activeRequests)

		case <-ticker.C:
			activeRequests := h.getActiveRequests()
			if activeRequests == 0 {
				shutdownLogger.Info().
					Dur("wait_duration", time.Since(start)).
					Msg("所有活跃请求已完成，API处理器关闭完成")
				return nil
			}

			shutdownLogger.Debug().
				Int("remaining_requests", activeRequests).
				Dur("wait_duration", time.Since(start)).
				Msg("等待活跃请求完成")
		}
	}
}

// GetMetrics 获取处理器指标
func (h *Handler) GetMetrics() gin.H {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return gin.H{
		"active_requests": h.activeRequests,
		"max_concurrent":  h.config.MaxConcurrentRequests,
		"request_timeout": h.config.RequestTimeout.String(),
	}
}

// 如果需要，可以添加配置验证方法
func (cfg *HandlerConfig) Validate() error {
	if cfg.RequestTimeout <= 0 {
		return fmt.Errorf("RequestTimeout必须大于0")
	}
	if cfg.MaxConcurrentRequests <= 0 {
		return fmt.Errorf("MaxConcurrentRequests必须大于0")
	}
	return nil
}
