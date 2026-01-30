package main

import (
	"context"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"url-checker/cmd/app"
	"url-checker/internal/config"
)

func main() {
	// 1. 创建根上下文和取消函数
	mainCtx, mainCancel := context.WithCancel(context.Background())
	defer mainCancel()

	// 2. 早期初始化结构化日志（控制台格式）
	logger := zerolog.New(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	}).With().
		Timestamp().
		Caller().
		Logger()

	// 3. 配置加载
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal().
			Err(err).
			Str("phase", "config_loading").
			Msg("Failed to load configuration")
	}

	// 4. 设置日志级别
	level, _ := zerolog.ParseLevel(cfg.Log.Level)
	zerolog.SetGlobalLevel(level)

	// 5. 添加请求ID和组件信息
	requestID := uuid.New().String()
	logger = logger.With().
		Str("request_id", requestID).
		Str("component", "main").
		Logger()

	// 6. 记录启动信息
	logger.Info().
		Str("version", "1.0.0").
		Str("go_version", runtime.Version()).
		Str("env", cfg.Server.Env).
		Str("port", cfg.Server.Port).
		Msg("Application starting")

	// 7. 直接初始化应用实例
	application, err := app.NewApplication(cfg, logger)
	if err != nil {
		logger.Fatal().
			Err(err).
			Str("phase", "app_init").
			Msg("Failed to create application")
	}

	// 8. 创建 errgroup（注意不要覆盖外部的 ctx）
	g, ctx := errgroup.WithContext(mainCtx)

	// 9. 启动应用（需要修改 Run 方法接收上下文）
	g.Go(func() error {
		logger.Info().Msg("Starting application")

		// 4. 创建服务器上下文（继承自主上下文）
		serverCtx, serverCancel := context.WithCancel(mainCtx)
		defer serverCancel()

		// 5. 启动服务器
		serverErr := make(chan error, 1)

		// 启动服务器
		go func() {
			if err := application.Run(serverCtx); err != nil {
				serverErr <- err
			}
		}()

		// 监听上下文取消和服务器错误
		select {
		case err := <-serverErr:
			logger.Error().Err(err).Msg("Application failed to start")
			return err
		case <-ctx.Done():
			logger.Info().Msg("Application context cancelled, initiating shutdown")

			// 优雅关闭
			shutdownCtx, shutdownCancel := context.WithTimeout(
				context.Background(),
				cfg.Server.ShutdownTimeout,
			)
			defer shutdownCancel()

			shutdownErr := application.Shutdown(shutdownCtx)

			// 返回shutdown的错误，如果没有则返回runErr（如果不是http.ErrServerClosed）
			if shutdownErr != nil {
				return shutdownErr
			}

			return nil
		}
	})

	// 10. 信号处理
	g.Go(func() error {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

		defer signal.Stop(sigChan) // 停止信号监听

		select {
		case sig := <-sigChan:
			logger.Info().
				Str("signal", sig.String()).
				Msg("Received shutdown signal")
			// 取消根上下文，触发应用关闭
			mainCancel()
			return nil // 这个 goroutine 返回 nil，让 errgroup 继续等待应用关闭

		case <-ctx.Done():
			// 上下文已取消（可能是应用自身出错）
			return ctx.Err()
		}
	})

	// 11. 等待所有 goroutine 完成
	if err := g.Wait(); err != nil {
		if err == context.Canceled {
			logger.Info().Msg("Application shutdown completed")
		} else {
			logger.Error().
				Err(err).
				Msg("Application terminated with error")
			os.Exit(1)
		}
	} else {
		logger.Info().Msg("Application shutdown gracefully")
	}
}
