// cmd/main.go
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"url-checker/cmd/app"
	"url-checker/internal/config"
)

func main() {
	// 加载配置
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	// 创建应用
	application, err := app.NewApplication(cfg)
	if err != nil {
		panic(err)
	}

	// 启动应用
	if err := application.Run(); err != nil {
		panic(err)
	}

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// 优雅关闭
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := application.Shutdown(ctx); err != nil {
		panic(err)
	}

	os.Exit(0)
}
