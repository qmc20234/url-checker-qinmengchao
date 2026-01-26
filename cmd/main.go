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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	// 4. 根据配置重新配置日志
	if cfg.Log.Format == "json" {
		logger = zerolog.New(os.Stdout).
			With().
			Timestamp().
			Caller().
			Logger()
	}
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

	// // 7. 构建依赖容器
	// container, err := di.BuildContainer(cfg, logger)
	// if err != nil {
	// 	logger.Fatal().
	// 		Err(err).
	// 		Str("phase", "di_container").
	// 		Msg("Failed to build dependency container")
	// }

	// // 8. 从容器获取应用
	// var application *app.Application
	// if err := container.Invoke(func(app *app.Application) {
	// 	application = app
	// }); err != nil {
	// 	logger.Fatal().
	// 		Err(err).
	// 		Str("phase", "di_invoke").
	// 		Msg("Failed to resolve application dependencies")
	// }
	// 7. 直接初始化应用实例（替换掉原来的第7、8步）
	application, err := app.NewApplication(cfg, logger)
	if err != nil {
		logger.Fatal().
			Err(err).
			Str("phase", "app_init").
			Msg("Failed to create application")
	}

	// 9. 使用errgroup管理goroutine
	g, ctx := errgroup.WithContext(ctx)

	// 启动应用
	g.Go(func() error {
		logger.Info().Msg("Starting application")
		if err := application.Run(); err != nil {
			return err
		}
		return nil
	})

	// 10. 信号处理
	g.Go(func() error {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

		select {
		case sig := <-sigChan:
			logger.Info().
				Str("signal", sig.String()).
				Msg("Received shutdown signal")
			cancel()

			// 优雅关闭
			shutdownCtx, shutdownCancel := context.WithTimeout(
				context.Background(),
				cfg.Server.ShutdownTimeout,
			)
			defer shutdownCancel()

			if err := application.Shutdown(shutdownCtx); err != nil {
				logger.Error().
					Err(err).
					Msg("Application shutdown with errors")
			}
			return nil

		case <-ctx.Done():
			return ctx.Err()
		}
	})

	// 11. 等待所有goroutine完成
	if err := g.Wait(); err != nil {
		logger.Error().
			Err(err).
			Msg("Application terminated with error")
		os.Exit(1)
	}

	logger.Info().Msg("Application shutdown gracefully")
}
