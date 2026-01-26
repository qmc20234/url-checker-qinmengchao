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

// NewApplication 应用构造函数
func NewApplication(cfg *config.Config) (*Application, error) {
	app := &Application{
		config:    cfg,
		startTime: time.Now(),
	}

	// 按顺序初始化组件
	if err := app.initLogger(); err != nil {
		return nil, fmt.Errorf("初始化日志失败: %w", err)
	}

	if err := app.initChecker(); err != nil {
		return nil, fmt.Errorf("初始化检查器失败: %w", err)
	}

	if err := app.initHandler(); err != nil {
		return nil, fmt.Errorf("初始化API处理器: %w", err)
	}

	if err := app.initRouter(); err != nil {
		return nil, fmt.Errorf("初始化路由失败: %w", err)
	}

	if err := app.initServer(); err != nil {
		return nil, fmt.Errorf("初始化路由失败: %w", err)
	}
	app.logger.Info().
		Str("version", "1.0.0").
		Msg("应用初始化完成")

	return app, nil
}

// initLogger 初始化日志系统
func (app *Application) initLogger() error {
	// 配置zerolog
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack

	// 设置日志级别
	logLevel := app.config.Log.Level
	if os.Getenv("DEBUG") == "true" {
		logLevel = "debug"
	}

	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// 设置日志输出
	var output io.Writer = os.Stdout

	switch app.config.Log.Format {
	case "console":
		output = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}
	case "json":
		output = os.Stdout
	default:
		output = os.Stdout
	}

	// 创建logger
	app.logger = zerolog.New(output).
		With().
		Timestamp().
		Caller().
		Str("service", "url-checker").
		Logger()

	return nil
}

// initChecker 初始化URL检查器
func (app *Application) initChecker() error {
	// 创建checker配置
	checkerCfg := checker.Config{
		MaxConcurrent:  app.config.Checker.MaxConcurrent,
		Timeout:        app.config.Checker.Timeout,
		MaxRetries:     app.config.Checker.MaxRetries,
		RetryInterval:  app.config.Checker.RetryInterval,
		MaxRedirects:   app.config.Checker.MaxRedirects,
		UserAgent:      app.config.Checker.UserAgent,
		AllowInsecure:  app.config.Checker.AllowInsecure,
		FollowRedirect: app.config.Checker.FollowRedirect,
		SSLCheck:       app.config.SSL.CheckEnabled,
	}

	var err error
	app.checker, err = checker.NewChecker(checkerCfg, app.logger)
	if err != nil {
		return fmt.Errorf("创建检查器失败: %w", err)
	}

	app.logger.Info().
		Int("max_concurrent", app.config.Checker.MaxConcurrent).
		Dur("timeout", app.config.Checker.Timeout).
		Msg("URL检查器初始化完成")

	return nil
}

// initHandler 初始化API处理器
func (app *Application) initHandler() error {
	app.handler = api.NewHandler(app.checker, app.logger)
	app.logger.Debug().Msg("API处理器初始化完成")
	return nil
}

// initRouter 初始化路由
func (app *Application) initRouter() error {
	// 设置Gin模式
	if app.config.Server.Env == "production" || os.Getenv("GIN_MODE") == "release" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// 创建Gin实例
	app.router = gin.New()

	// 中间件
	app.router.Use(gin.Recovery())
	app.router.Use(app.loggingMiddleware())

	// CORS配置
	app.router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// 注册路由
	app.registerRoutes()

	app.logger.Debug().Msg("路由初始化完成")
	return nil
}

// initServer 初始化HTTP服务器
func (app *Application) initServer() error {
	app.server = &http.Server{
		Addr:         ":" + app.config.Server.Port,
		Handler:      app.router,
		ReadTimeout:  app.config.Server.ReadTimeout,
		WriteTimeout: app.config.Server.WriteTimeout,
		IdleTimeout:  app.config.Server.IdleTimeout,
	}

	app.logger.Debug().
		Str("addr", app.server.Addr).
		Msg("HTTP服务器初始化完成")

	return nil
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

// loggingMiddleware 日志中间件
func (app *Application) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// 处理请求
		c.Next()

		// 记录日志
		latency := time.Since(start)

		logger := app.logger.Info()
		if c.Writer.Status() >= 400 {
			logger = app.logger.Warn()
		}
		if c.Writer.Status() >= 500 {
			logger = app.logger.Error()
		}

		logger.
			Str("method", c.Request.Method).
			Str("path", c.Request.URL.Path).
			Int("status", c.Writer.Status()).
			Str("ip", c.ClientIP()).
			Dur("latency", latency).
			Str("user_agent", c.Request.UserAgent()).
			Msg("HTTP请求")
	}
}

// Run 启动应用
func (app *Application) Run() error {
	app.logger.Info().
		Str("port", app.config.Server.Port).
		Str("env", app.config.Server.Env).
		Int("max_concurrent", app.config.Checker.MaxConcurrent).
		Msg("URL检查器服务启动中...")

	// 启动HTTP服务器
	go func() {
		if err := app.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			app.logger.Fatal().Err(err).Msg("服务器启动失败")
		}
	}()

	return nil
}

// Shutdown 优雅关闭
func (app *Application) Shutdown(ctx context.Context) error {
	app.logger.Info().Msg("正在关闭应用...")

	// 关闭checker
	if app.checker != nil {
		if err := app.checker.Shutdown(); err != nil {
			app.logger.Error().Err(err).Msg("检查器关闭失败")
			return err
		}
	}

	// 关闭HTTP服务器
	if err := app.server.Shutdown(ctx); err != nil {
		app.logger.Error().Err(err).Msg("HTTP服务器关闭失败")
		return err
	}

	app.logger.Info().Msg("应用已关闭")
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
