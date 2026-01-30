package app

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

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
	mu        sync.RWMutex
	isRunning bool
}

// NewApplication 应用构造函数
func NewApplication(cfg *config.Config, logger zerolog.Logger) (*Application, error) {
	app := &Application{
		config:    cfg,
		logger:    logger,
		startTime: time.Now(),
	}

	// 初始化检查器
	if err := app.initChecker(); err != nil {
		// 注意：initChecker 内部已经处理了日志记录
		return nil, fmt.Errorf("初始化检查器失败: %w", err)
	}

	// 初始化处理器
	if err := app.initHandler(); err != nil {
		// 注意：initChecker 内部已经处理了日志记录
		return nil, fmt.Errorf("初始化处理器失败: %w", err)
	}

	// 初始化路由
	if err := app.initRouter(); err != nil {
		return nil, fmt.Errorf("初始化路由失败: %w", err)
	}

	// 初始化服务器
	if err := app.initServer(); err != nil {
		return nil, fmt.Errorf("初始化服务器失败: %w", err)
	}

	app.logger.Info().
		Str("phase", "startup").
		Dur("initialization_duration", time.Since(app.startTime)).
		Msg("应用初始化完成")

	return app, nil
}

// initChecker 初始化检查器
func (app *Application) initChecker() error {
	// 使用config包中的配置初始化checker
	var err error
	app.checker, err = checker.NewChecker(app.config.Checker, app.config.SSL, app.logger)
	if err != nil {
		app.logger.Error().
			Err(err).
			Int("max_concurrent", app.config.Checker.MaxConcurrent).
			Dur("timeout", app.config.Checker.Timeout).
			Bool("allow_insecure", app.config.Checker.AllowInsecure).
			Msg("检查器创建失败")
		return fmt.Errorf("创建检查器失败: %w", err)
	}

	app.logger.Info().
		Str("phase", "initialization").
		Int("max_concurrent", app.config.Checker.MaxConcurrent).
		Dur("timeout", app.config.Checker.Timeout).
		Msg("URL检查器初始化完成")

	return nil
}

// initHandler 初始化API处理器
func (app *Application) initHandler() error {
	handlerConfig := api.DefaultHandlerConfig()

	app.handler = api.NewHandler(app.checker, app.logger, handlerConfig)
	app.logger.Info().Msg("API处理器初始化完成")
	return nil
}

// initRouter 初始化路由
func (app *Application) initRouter() error {
	// 根据环境设置Gin模式
	if app.config.Server.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	app.router = gin.New()

	// 使用Gin的Recovery中间件
	app.router.Use(gin.Recovery())

	// 使用自定义的日志中间件
	app.router.Use(app.loggingMiddleware())

	// CORS配置
	app.router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"}, // 生产环境建议限制来源
		AllowMethods:     []string{"GET"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// 注册路由
	app.registerRoutes()

	app.logger.Debug().Msg("路由与中间件初始化完成")
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

	app.logger.Info().
		Str("addr", ":"+app.config.Server.Port).
		Dur("read_timeout", app.config.Server.ReadTimeout).
		Dur("write_timeout", app.config.Server.WriteTimeout).
		Dur("idle_timeout", app.config.Server.IdleTimeout).
		Msg("HTTP服务器配置完成")

	return nil
}

// loggingMiddleware 日志中间件
func (app *Application) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 为每个请求生成唯一ID
		requestID := uuid.New().String()
		start := time.Now()
		path := c.Request.URL.Path

		// 将请求ID存入Gin上下文
		c.Set("request_id", requestID)

		// 创建请求上下文Logger
		requestLogger := app.logger.With().
			Str("request_id", requestID).
			Str("method", c.Request.Method).
			Str("path", path).
			Str("client_ip", c.ClientIP()).
			Logger()

		// 将requestLogger存入上下文
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
		// 可以添加更多接口
	}
}

// GetRequestLogger 从Gin上下文中获取请求Logger
func GetRequestLogger(c *gin.Context) zerolog.Logger {
	if logger, exists := c.Get("logger"); exists {
		if l, ok := logger.(zerolog.Logger); ok {
			return l
		}
	}
	// 如果上下文中没有，回退到全局Logger
	return zerolog.Nop()
}

// Run 启动应用（阻塞版本）
func (app *Application) Run(ctx context.Context) error {
	app.mu.Lock()
	if app.isRunning {
		app.mu.Unlock()
		return fmt.Errorf("应用已经在运行")
	}
	app.isRunning = true
	app.mu.Unlock()

	app.logger.Info().
		Str("phase", "startup").
		Str("port", app.config.Server.Port).
		Str("env", app.config.Server.Env).
		Msg("URL检查器服务启动中")

	// 创建错误通道
	serverErr := make(chan error, 1)

	// 启动服务器
	go func() {
		app.logger.Info().Str("address", ":"+app.config.Server.Port).Msg("HTTP服务器开始监听")

		if err := app.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			app.logger.Error().
				Err(err).
				Str("phase", "startup").
				Msg("HTTP服务器启动失败")
			serverErr <- err
		} else {
			serverErr <- nil
		}
	}()

	// 监听多个事件
	select {
	case <-ctx.Done():
		app.logger.Info().Msg("收到关闭信号，开始优雅关闭")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), app.config.Server.ShutdownTimeout)
		defer cancel()

		return app.Shutdown(shutdownCtx)

	case err := <-serverErr:
		if err != nil {
			// 服务器启动失败，尝试清理资源
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			app.Shutdown(shutdownCtx) // 忽略错误，因为我们已经在错误状态
			return err
		}
		return nil
	}
}

// Shutdown 优雅关闭
func (app *Application) Shutdown(ctx context.Context) error {
	app.mu.Lock()
	if !app.isRunning {
		app.mu.Unlock()
		return nil // 已经关闭
	}
	app.isRunning = false
	app.mu.Unlock()

	shutdownLogger := app.logger.With().Str("phase", "shutdown").Logger()
	shutdownLogger.Info().Msg("开始应用关闭流程")

	shutdownStart := time.Now()

	// 使用 errgroup 管理关闭操作
	g, shutdownCtx := errgroup.WithContext(ctx)

	// 1. 关闭HTTP服务器
	if app.server != nil {
		g.Go(func() error {
			shutdownLogger.Debug().Msg("正在关闭HTTP服务器...")

			serverShutdownCtx, cancel := context.WithTimeout(shutdownCtx, 30*time.Second)
			defer cancel()

			if err := app.server.Shutdown(serverShutdownCtx); err != nil {
				shutdownLogger.Error().Err(err).Msg("HTTP服务器关闭失败")
				return fmt.Errorf("HTTP服务器关闭失败: %w", err)
			}

			shutdownLogger.Info().Msg("HTTP服务器已关闭")
			return nil
		})
	}

	// 2. 在主关闭流程中添加handler关闭
	if app.handler != nil {
		g.Go(func() error {
			shutdownLogger.Debug().Msg("正在关闭Handler资源...")

			handlerShutdownCtx, cancel := context.WithTimeout(shutdownCtx, 15*time.Second)
			defer cancel()

			if err := app.handler.Shutdown(handlerShutdownCtx); err != nil {
				shutdownLogger.Error().Err(err).Msg("Handler资源关闭失败")
				return fmt.Errorf("Handler资源关闭失败: %w", err)
			}

			shutdownLogger.Info().Msg("Handler资源已关闭")
			return nil
		})
	}

	// 2. 关闭检查器
	if app.checker != nil {
		g.Go(func() error {
			shutdownLogger.Debug().Msg("正在关闭URL检查器...")

			checkerShutdownCtx, cancel := context.WithTimeout(shutdownCtx, 10*time.Second)
			defer cancel()

			if err := app.checker.Shutdown(checkerShutdownCtx); err != nil {
				shutdownLogger.Error().Err(err).Msg("URL检查器关闭失败")
				return fmt.Errorf("URL检查器关闭失败: %w", err)
			}

			shutdownLogger.Info().Msg("URL检查器已关闭")
			return nil
		})
	}

	// 等待所有关闭操作完成
	err := g.Wait()

	shutdownLogger.Info().
		Dur("total_uptime", time.Since(app.startTime)).
		Dur("shutdown_duration", time.Since(shutdownStart)).
		Err(err).
		Msg("应用关闭完成")

	return err
}

// IsReady 检查应用是否就绪
func (app *Application) IsReady() bool {
	app.mu.RLock()
	defer app.mu.RUnlock()

	return app.isRunning && app.checker != nil
}

// GetRouter 获取路由（用于测试）
func (app *Application) GetRouter() *gin.Engine {
	return app.router
}

// GetLogger 获取日志器
func (app *Application) GetLogger() zerolog.Logger {
	return app.logger
}

// GetConfig 获取配置
func (app *Application) GetConfig() *config.Config {
	return app.config
}
