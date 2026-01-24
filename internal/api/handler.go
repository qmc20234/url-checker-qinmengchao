package api

import (
    "net/http"
    "time"
    
    "github.com/gin-gonic/gin"
    "url-checker/internal/checker"
    "url-checker/internal/models"
)

// Handler HTTP请求处理器
type Handler struct {
    checker *checker.Checker
}

// NewHandler 创建处理器
func NewHandler(checker *checker.Checker) *Handler {
    return &Handler{checker: checker}
}

// HealthCheck 健康检查
func (h *Handler) HealthCheck(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
        "status": "healthy",
        "timestamp": time.Now().Unix(),
    })
}

// BatchCheck 批量检查URL
func (h *Handler) BatchCheck(c *gin.Context) {
    var req models.CheckRequest
    
    // 绑定JSON请求
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "无效的请求格式: " + err.Error(),
        })
        return
    }
    
    // 验证URL数量
    if len(req.URLs) > 100 {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "最多支持100个URL",
        })
        return
    }
    
    // 执行批量检查
    startTime := time.Now()
    results := h.checker.BatchCheck(c.Request.Context(), req.URLs)
    duration := time.Since(startTime)
    
    // 构建响应
    response := models.BatchResponse{
        TaskID:   generateTaskID(),
        Status:   "completed",
        Results:  results,
        Total:    len(results),
        Duration: duration.String(),
    }
    
    c.JSON(http.StatusOK, response)
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
