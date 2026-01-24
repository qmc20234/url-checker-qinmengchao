package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"

	"url-checker/internal/api"
	"url-checker/internal/checker"
	"url-checker/internal/config"
)

func main() {
	// 配置日志
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack

	logLevel := zerolog.InfoLevel
	if os.Getenv("DEBUG") == "true" {
		logLevel = zerolog.DebugLevel
	}
	zerolog.SetGlobalLevel(logLevel)

	logger := zerolog.New(os.Stdout).
		With().
		Timestamp().
		Caller().
		Logger()

	// 加载配置
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal().Err(err).Msg("加载配置失败")
	}

	// 初始化检查器
	urlChecker := checker.NewChecker(
		cfg.Checker.MaxConcurrent,
		cfg.Checker.Timeout,
	)

	// 初始化处理器
	handler := api.NewHandler(urlChecker)

	// 设置Gin模式
	if os.Getenv("GIN_MODE") == "release" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// 创建Gin路由
	r := gin.New()

	// 中间件
	r.Use(gin.Recovery())
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// 静态文件服务
	// r.Static("/static", "./web/static")
	// r.StaticFile("/", "./web/static/index.html")

	// API路由
	apiGroup := r.Group("/api")
	{
		apiGroup.GET("/health", handler.HealthCheck)
		apiGroup.POST("/check", handler.BatchCheck)
		// 可以添加更多API端点
	}

	// 创建HTTP服务器
	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// 优雅关闭
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("服务器启动失败")
		}
	}()

	logger.Info().
		Str("port", cfg.Server.Port).
		Int("max_concurrent", cfg.Checker.MaxConcurrent).
		Msg("URL检查器服务已启动")

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info().Msg("正在关闭服务器...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal().Err(err).Msg("服务器关闭失败")
	}

	logger.Info().Msg("服务器已关闭")
}
