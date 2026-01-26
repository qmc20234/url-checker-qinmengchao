package app

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"

	"url-checker/internal/api"
	"url-checker/internal/checker"
	"url-checker/internal/config"
)

// Application 应用主结构体
type Application struct {
	config    *config.Config
	logger    zerolog.Logger
	checker   *checker.Checker
	handler   *api.Handler
	router    *gin.Engine
	server    *http.Server
	startTime time.Time
}

type serverConfig struct {
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	Env          string
}

// NewApplication 应用构造函数 (优化后)
// 职责清晰：仅接受配置，负责创建所有依赖（包括Logger）
func NewApplication(cfg *config.Config, logger zerolog.Logger) (*Application, error) {
	app := &Application{
		config:    cfg,
		startTime: time.Now(),
		logger:    logger,
	}

	// 后续初始化步骤，传入专属配置
	if err := app.initChecker(); err != nil {
		return nil, fmt.Errorf("init checker: %w", err)
	}
	if err := app.initHandler(); err != nil {
		return nil, fmt.Errorf("init handler: %w", err)
	}
	if err := app.initRouter(); err != nil {
		return nil, fmt.Errorf("init router: %w", err)
	}
	if err := app.initServer(); err != nil {
		return nil, fmt.Errorf("init server: %w", err)
	}

	app.logger.Info().
		Str("phase", "startup").
		Dur("initialization_duration", time.Since(app.startTime)).
		Msg("应用初始化完成")

	return app, nil
}

// initLogger 初始化日志系统 (优化后)
func (app *Application) initLogger() error {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack

	// 设置日志级别（环境变量优先级最高）
	logLevel := app.config.Log.Level
	if os.Getenv("DEBUG") == "true" {
		logLevel = "debug"
	}
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		level = zerolog.InfoLevel
		// 注意：此时还没有app.logger，无法记录警告
	}
	zerolog.SetGlobalLevel(level)

	// 设置输出
	var output io.Writer = os.Stdout
	if app.config.Log.Format == "console" {
		consoleWriter := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
			NoColor:    app.config.Server.Env == "production", // 生产环境禁用颜色
		}
		output = consoleWriter
	}

	// 创建带有服务上下文的核心Logger
	app.logger = zerolog.New(output).
		With().
		Timestamp().
		Caller().
		Str("service", "url-checker").
		Str("environment", app.config.Server.Env).
		Logger()

	// 使用新的Logger记录配置情况
	app.logger.Debug().
		Str("log_level", level.String()).
		Str("log_format", app.config.Log.Format).
		Msg("日志系统配置完成")

	return nil
}

// initChecker 使用专属配置初始化检查器
func (app *Application) initChecker() error {
	cfg := checker.CheckerConfig{
		HTTP: checker.HTTPConfig{
			Timeout:             app.config.Checker.Timeout,
			MaxRetries:          app.config.Checker.MaxRetries,
			RetryInterval:       app.config.Checker.RetryInterval,
			MaxRedirects:        app.config.Checker.MaxRedirects,
			UserAgent:           app.config.Checker.UserAgent,
			AllowInsecure:       app.config.Checker.AllowInsecure,
			FollowRedirect:      app.config.Checker.FollowRedirect,
			TLSHandshakeTimeout: 5 * time.Second,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Pool: checker.PoolConfig{
			MaxConcurrent: app.config.Checker.MaxConcurrent,
			BatchTimeout:  5 * time.Minute,
		},
	}

	var err error
	app.checker, err = checker.NewChecker(cfg, app.logger)
	if err != nil {
		// 使用结构化日志记录失败时的配置快照，便于调试
		app.logger.Error().
			Err(err).
			Int("max_concurrent", cfg.Pool.MaxConcurrent).
			Dur("timeout", cfg.HTTP.Timeout).
			Bool("allow_insecure", cfg.HTTP.AllowInsecure).
			Msg("检查器创建失败")
		return fmt.Errorf("create checker: %w", err)
	}

	app.logger.Info().
		Str("phase", "initialization").
		Int("max_concurrent", cfg.Pool.MaxConcurrent).
		Dur("timeout", cfg.HTTP.Timeout).
		Msg("URL检查器初始化完成")
	return nil
}

// initHandler 初始化API处理器
func (app *Application) initHandler() error {
	handlerConfig := api.HandlerConfig{
		ValidationMessages: map[string]string{
			"required": "缺少必要参数 %s",
			"url":      "URL格式无效: %v",
		},
		RequestTimeout: 60 * time.Second,
	}

	app.handler = api.NewHandler(app.checker, app.logger, handlerConfig)
	app.logger.Info().Msg("API处理器初始化完成")
	return nil
}

// initServer 使用专属配置初始化HTTP服务器
func (app *Application) initServer() error {
	cfg := serverConfig{
		Addr:         ":" + app.config.Server.Port,
		ReadTimeout:  app.config.Server.ReadTimeout,
		WriteTimeout: app.config.Server.WriteTimeout,
		IdleTimeout:  app.config.Server.IdleTimeout,
		Env:          app.config.Server.Env,
	}

	app.server = &http.Server{
		Addr:         cfg.Addr,
		Handler:      app.router,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	app.logger.Debug().
		Str("addr", cfg.Addr).
		Dur("read_timeout", cfg.ReadTimeout).
		Dur("idle_timeout", cfg.IdleTimeout).
		Msg("HTTP服务器配置完成")
	return nil
}

// --- 优化2: 增强的日志中间件，支持请求链路追踪 ---
func (app *Application) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 为每个请求生成唯一ID
		requestID := uuid.New().String()
		start := time.Now()
		path := c.Request.URL.Path

		// 将请求ID存入Gin上下文，供后续处理程序使用
		c.Set("request_id", requestID)

		// 创建请求上下文Logger，继承全局Logger的字段并添加请求特定字段
		requestLogger := app.logger.With().
			Str("request_id", requestID).
			Str("method", c.Request.Method).
			Str("path", path).
			Str("client_ip", c.ClientIP()).
			Logger()

		// 可选：将requestLogger也存入上下文，方便handler获取
		c.Set("logger", requestLogger)

		// 处理请求
		c.Next()

		// 记录请求完成日志
		latency := time.Since(start)
		status := c.Writer.Status()

		// 根据状态码选择日志级别
		logEvent := requestLogger.Info()
		if status >= 400 && status < 500 {
			logEvent = requestLogger.Warn()
		} else if status >= 500 {
			logEvent = requestLogger.Error()
		}

		// 记录结构化的请求摘要
		logEvent.
			Int("status_code", status).
			Dur("latency_ms", latency).
			Int("response_size_bytes", c.Writer.Size()).
			Str("user_agent", c.Request.UserAgent()).
			Msg("HTTP请求")
	}
}

// registerRoutes 注册路由
func (app *Application) registerRoutes() {
	// API路由
	apiGroup := app.router.Group("/api")
	{
		// 检查接口
		apiGroup.GET("/check", app.handler.CheckStream)
	}
}

// initRouter 初始化路由（集成优化后的中间件）
func (app *Application) initRouter() error {
	if app.config.Server.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	app.router = gin.New()
	app.router.Use(gin.Recovery())
	// 使用优化后的日志中间件
	app.router.Use(app.loggingMiddleware())

	// CORS配置（可从配置读取）
	app.router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"}, // 建议配置化：app.config.Server.CORS.AllowOrigins
		AllowMethods:     []string{"GET"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	app.registerRoutes()
	app.logger.Debug().Msg("路由与中间件初始化完成")
	return nil
}

// 辅助函数：供Handler从Gin上下文中获取请求Logger的示例
func GetRequestLogger(c *gin.Context) zerolog.Logger {
	if logger, exists := c.Get("logger"); exists {
		if l, ok := logger.(zerolog.Logger); ok {
			return l
		}
	}
	// 如果上下文中没有，回退到全局Logger（应避免）
	return zerolog.Nop()
}

// Shutdown 优雅关闭（优化日志）
func (app *Application) Shutdown(ctx context.Context) error {
	shutdownLogger := app.logger.With().Str("phase", "shutdown").Logger()
	shutdownLogger.Info().Msg("开始应用关闭流程")

	// 先关闭HTTP服务器，停止接收新请求
	if app.server != nil {
		shutdownLogger.Debug().Msg("正在关闭HTTP服务器...")
		if err := app.server.Shutdown(ctx); err != nil {
			shutdownLogger.Error().Err(err).Msg("HTTP服务器关闭失败")
			return fmt.Errorf("server shutdown: %w", err)
		}
		shutdownLogger.Info().Msg("HTTP服务器已关闭")
	}

	// 再关闭业务组件
	if app.checker != nil {
		shutdownLogger.Debug().Msg("正在关闭URL检查器...")
		if err := app.checker.Shutdown(); err != nil {
			shutdownLogger.Error().Err(err).Msg("URL检查器关闭失败")
			return fmt.Errorf("checker shutdown: %w", err)
		}
		shutdownLogger.Info().Msg("URL检查器已关闭")
	}

	shutdownLogger.Info().
		Dur("total_uptime", time.Since(app.startTime)).
		Msg("应用关闭完成")
	return nil
}

// Run 启动应用（优化日志）
func (app *Application) Run() error {
	app.logger.Info().
		Str("phase", "startup").
		Str("port", app.config.Server.Port).
		Str("env", app.config.Server.Env).
		Msg("URL检查器服务启动中")

	go func() {
		if err := app.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			app.logger.Fatal().
				Err(err).
				Str("phase", "startup").
				Msg("HTTP服务器启动失败")
		}
	}()
	return nil
}

// GetRouter 获取路由（用于测试）
func (app *Application) GetRouter() *gin.Engine {
	return app.router
}

// GetLogger 获取日志器（用于测试）
func (app *Application) GetLogger() zerolog.Logger {
	return app.logger
}
