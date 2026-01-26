package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
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
}

// 默认配置
var DefaultHandlerConfig = HandlerConfig{
	ValidationMessages: map[string]string{
		"required": "参数 %s 为必填项",
		"url":      "参数 %s 包含无效的URL格式: %v",
		"min":      "参数 %s 至少需要 %v 个元素",
		"max":      "参数 %s 最多允许 %v 个元素",
		"dive":     "参数 %s 中的元素验证失败",
	},
	SSEHeaders: map[string]string{
		"Content-Type":      "text/event-stream",
		"Cache-Control":     "no-cache",
		"Connection":        "keep-alive",
		"X-Accel-Buffering": "no",
	},
	RequestTimeout: 30 * time.Second,
}

// Handler HTTP请求处理器
type Handler struct {
	checker *checker.Checker
	logger  zerolog.Logger
	config  HandlerConfig
}

// NewHandler 创建处理器（支持自定义配置）
func NewHandler(checker *checker.Checker, logger zerolog.Logger, config ...HandlerConfig) *Handler {
	cfg := DefaultHandlerConfig
	if len(config) > 0 {
		cfg = config[0]
	}

	return &Handler{
		checker: checker,
		logger:  logger,
		config:  cfg,
	}
}

// CheckRequest 检查请求参数
type CheckRequest struct {
	URLs []string `form:"urls" binding:"required,min=1,max=100,dive,required,url"`
}

// --- 优化2: 增强的日志上下文工具函数 ---
// 从Gin上下文获取请求专用的Logger（与之前优化的中间件配合）
func getRequestLogger(c *gin.Context) zerolog.Logger {
	if logger, exists := c.Get("logger"); exists {
		if l, ok := logger.(zerolog.Logger); ok {
			return l
		}
	}
	// 回退到全局Logger（添加标记以便识别）
	return zerolog.Nop().With().Str("context", "fallback_global").Logger()
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
	// 获取请求专用的Logger（包含request_id）
	requestLogger := getRequestLogger(c)

	// 记录请求开始
	requestLogger.Info().
		Str("handler", "CheckStream").
		Str("client_ip", c.ClientIP()).
		Str("user_agent", c.Request.UserAgent()).
		Msg("开始处理URL检查请求")

	// 绑定并验证参数
	var req CheckRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		h.handleValidationError(c, err)
		return
	}

	// 记录验证成功的参数摘要
	requestLogger.Info().
		Int("url_count", len(req.URLs)).
		Str("urls_sample", getURLsSample(req.URLs)). // 避免记录所有URL
		Msg("请求参数验证成功")

	// 设置SSE响应头（使用配置）
	for key, value := range h.config.SSEHeaders {
		c.Header(key, value)
	}

	// 设置请求超时上下文
	ctx := c.Request.Context()
	if h.config.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.config.RequestTimeout)
		defer cancel()

		requestLogger.Debug().
			Dur("request_timeout", h.config.RequestTimeout).
			Msg("设置请求超时上下文")
	}

	// 记录批量检查开始
	batchStart := time.Now()
	requestLogger.Info().
		Int("batch_size", len(req.URLs)).
		Msg("开始批量URL检查")

	// 获取结果流
	resultChan := h.checker.BatchCheck(ctx, req.URLs)

	// 流式发送
	sentCount := 0
	for _, result := range resultChan {
		// 发送SSE事件
		c.SSEvent("check", result)
		c.Writer.Flush()
		sentCount++

		// 可选：记录每个结果的摘要（避免日志过多）
		if requestLogger.GetLevel() == zerolog.DebugLevel {
			requestLogger.Debug().
				Str("url", result.URL).
				Int("status_code", result.StatusCode).
				Msg("发送检查结果")
		}

		// 检查连接是否断开
		if c.Writer.Status() == 0 || c.IsAborted() {
			requestLogger.Info().
				Int("sent_results", sentCount).
				Msg("客户端提前断开连接")
			return
		}
	}

	// 记录批量检查完成
	batchDuration := time.Since(batchStart)
	requestLogger.Info().
		Int("total_urls", len(req.URLs)).
		Int("sent_results", sentCount).
		Dur("batch_duration", batchDuration).
		Msg("批量URL检查完成")

	// 发送结束事件
	c.SSEvent("end", gin.H{
		"message": "检查完成",
		"stats": gin.H{
			"total_urls":   len(req.URLs),
			"duration_ms":  batchDuration.Milliseconds(),
			"completed_at": time.Now().Format(time.RFC3339),
		},
	})
	c.Writer.Flush()
}

// --- 辅助函数 ---

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

// 如果需要，可以添加配置验证方法
func (cfg *HandlerConfig) Validate() error {
	if cfg.RequestTimeout <= 0 {
		return fmt.Errorf("RequestTimeout必须大于0")
	}
	return nil
}
