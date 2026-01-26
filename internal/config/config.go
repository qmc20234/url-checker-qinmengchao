// internal/config/config.go
package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server  ServerConfig  `mapstructure:"server"`
	Log     LogConfig     `mapstructure:"log"`
	Checker CheckerConfig `mapstructure:"checker"`
	SSL     SSLConfig     `mapstructure:"ssl"`
}

type ServerConfig struct {
	Port         string        `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	// 添加新字段以支持更多功能
	IdleTimeout time.Duration `mapstructure:"idle_timeout"`
	Env         string        `mapstructure:"env"`
	MaxBodySize int64         `mapstructure:"max_body_size"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

type CheckerConfig struct {
	MaxConcurrent int           `mapstructure:"max_concurrent"`
	Timeout       time.Duration `mapstructure:"timeout"`
	MaxRetries    int           `mapstructure:"max_retries"`
	// 添加新字段以支持更多功能
	RetryInterval  time.Duration `mapstructure:"retry_interval"`
	MaxRedirects   int           `mapstructure:"max_redirects"`
	UserAgent      string        `mapstructure:"user_agent"`
	AllowInsecure  bool          `mapstructure:"allow_insecure"`
	FollowRedirect bool          `mapstructure:"follow_redirect"`
}

type SSLConfig struct {
	CheckEnabled bool `mapstructure:"check_enabled"`
	// 添加新字段
	WarnDaysBefore int `mapstructure:"warn_days_before"`
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")

	// 设置默认值 - 扩展默认配置
	setDefaults()

	// 读取环境变量 - 支持环境变量覆盖
	viper.AutomaticEnv()

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("读取配置文件失败: %w", err)
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}

	return &cfg, nil
}

func setDefaults() {
	// Server 默认值
	viper.SetDefault("server.port", "8080")
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.idle_timeout", "60s")
	viper.SetDefault("server.env", "development")
	viper.SetDefault("server.max_body_size", 1048576) // 1MB

	// Log 默认值
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", "json")
	viper.SetDefault("log.output", "stdout")

	// Checker 默认值
	viper.SetDefault("checker.max_concurrent", 10)
	viper.SetDefault("checker.timeout", "10s")
	viper.SetDefault("checker.max_retries", 3)
	viper.SetDefault("checker.retry_interval", "1s")
	viper.SetDefault("checker.max_redirects", 5)
	viper.SetDefault("checker.user_agent", "URL-Checker/1.0")
	viper.SetDefault("checker.allow_insecure", false)
	viper.SetDefault("checker.follow_redirect", true)

	// SSL 默认值
	viper.SetDefault("ssl.check_enabled", true)
	viper.SetDefault("ssl.warn_days_before", 30)
}
