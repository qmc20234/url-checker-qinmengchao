package config

import (
	"fmt"
	"strings"
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
	Port            string        `mapstructure:"port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	Env             string        `mapstructure:"env"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

// CheckerConfig - 简化配置，移除 SSL 相关字段
type CheckerConfig struct {
	// HTTP 配置
	Timeout             time.Duration `mapstructure:"timeout"`
	MaxRetries          int           `mapstructure:"max_retries"`
	RetryInterval       time.Duration `mapstructure:"retry_interval"`
	MaxRedirects        int           `mapstructure:"max_redirects"`
	UserAgent           string        `mapstructure:"user_agent"`
	AllowInsecure       bool          `mapstructure:"allow_insecure"`
	FollowRedirect      bool          `mapstructure:"follow_redirect"`
	TLSHandshakeTimeout time.Duration `mapstructure:"tls_handshake_timeout"`
	MaxIdleConnsPerHost int           `mapstructure:"max_idle_conns_per_host"`
	IdleConnTimeout     time.Duration `mapstructure:"idle_conn_timeout"`

	// Pool 配置
	MaxConcurrent int           `mapstructure:"max_concurrent"`
	BatchTimeout  time.Duration `mapstructure:"batch_timeout"`
}

// SSLConfig - 统一的 SSL 配置
type SSLConfig struct {
	InsecureSkipVerify bool          `mapstructure:"insecure_skip_verify"`
	Timeout            time.Duration `mapstructure:"timeout"`
}

// Validate 配置验证
func (c *Config) Validate() error {
	// 验证 Server 配置
	if c.Server.Port == "" {
		return fmt.Errorf("server.port 不能为空")
	}
	if c.Server.ReadTimeout <= 0 {
		return fmt.Errorf("server.read_timeout 必须大于0")
	}

	// 验证 Checker 配置
	if c.Checker.MaxConcurrent <= 0 {
		return fmt.Errorf("checker.max_concurrent 必须大于0")
	}
	if c.Checker.Timeout <= 0 {
		return fmt.Errorf("checker.timeout 必须大于0")
	}
	if c.Checker.MaxRetries < 0 {
		return fmt.Errorf("checker.max_retries 不能为负数")
	}

	// 验证 SSL 配置
	if c.SSL.Timeout <= 0 {
		return fmt.Errorf("ssl.timeout 必须大于0")
	}

	// 验证环境
	validEnvs := map[string]bool{
		"development": true,
		"staging":     true,
		"production":  true,
	}
	if !validEnvs[c.Server.Env] {
		return fmt.Errorf("server.env 必须是 development/staging/production")
	}

	// 验证日志级别
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
		"fatal": true,
	}
	if !validLogLevels[strings.ToLower(c.Log.Level)] {
		return fmt.Errorf("log.level 必须是 debug/info/warn/error/fatal")
	}

	return nil
}

// Load 加载配置
func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("../configs")
	viper.AddConfigPath(".")

	// 设置默认值
	setDefaults()

	// 设置环境变量
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	// 允许通过环境变量指定配置文件路径
	if configPath := viper.GetString("URL_CHECKER_CONFIG"); configPath != "" {
		viper.SetConfigFile(configPath)
	}

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("读取配置文件失败: %w", err)
		}
		// 配置文件不存在，使用默认值
		fmt.Println("警告: 配置文件未找到，使用默认配置")
	}

	// 解析配置
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}

	// 修复配置（确保所有时间字段都有有效值）
	fixConfig(&cfg)

	// 验证配置
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}

	// 根据环境调整配置
	postProcessConfig(&cfg)

	return &cfg, nil
}

func setDefaults() {
	// Server 默认值
	viper.SetDefault("server.port", "8080")
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.idle_timeout", "60s")
	viper.SetDefault("server.shutdown_timeout", "30s")
	viper.SetDefault("server.env", "development")
	viper.SetDefault("server.max_body_size", 1048576) // 1MB

	// Log 默认值
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.output", "stdout")

	// Checker 默认值 - HTTP 配置
	viper.SetDefault("checker.timeout", "10s")
	viper.SetDefault("checker.max_retries", 3)
	viper.SetDefault("checker.retry_interval", "1s")
	viper.SetDefault("checker.max_redirects", 5)
	viper.SetDefault("checker.user_agent", "URL-Checker/1.0")
	viper.SetDefault("checker.allow_insecure", false)
	viper.SetDefault("checker.follow_redirect", true)
	viper.SetDefault("checker.tls_handshake_timeout", "5s")
	viper.SetDefault("checker.max_idle_conns_per_host", 100)
	viper.SetDefault("checker.idle_conn_timeout", "90s")

	// Checker 默认值 - Pool 配置
	viper.SetDefault("checker.max_concurrent", 50)
	viper.SetDefault("checker.batch_timeout", "5m")

	// SSL 默认值
	viper.SetDefault("ssl.enabled", true)
	viper.SetDefault("ssl.insecure_skip_verify", false)
	viper.SetDefault("ssl.timeout", "10s")
}

func fixConfig(cfg *Config) {
	// 修复 Server 时间字段
	if cfg.Server.ReadTimeout == 0 {
		cfg.Server.ReadTimeout = 30 * time.Second
	}
	if cfg.Server.WriteTimeout == 0 {
		cfg.Server.WriteTimeout = 30 * time.Second
	}
	if cfg.Server.IdleTimeout == 0 {
		cfg.Server.IdleTimeout = 60 * time.Second
	}
	if cfg.Server.ShutdownTimeout == 0 {
		cfg.Server.ShutdownTimeout = 30 * time.Second
	}

	// 修复 Checker 时间字段
	if cfg.Checker.Timeout == 0 {
		cfg.Checker.Timeout = 10 * time.Second
	}
	if cfg.Checker.RetryInterval == 0 {
		cfg.Checker.RetryInterval = 1 * time.Second
	}
	if cfg.Checker.TLSHandshakeTimeout == 0 {
		cfg.Checker.TLSHandshakeTimeout = 5 * time.Second
	}
	if cfg.Checker.IdleConnTimeout == 0 {
		cfg.Checker.IdleConnTimeout = 90 * time.Second
	}
	if cfg.Checker.BatchTimeout == 0 {
		cfg.Checker.BatchTimeout = 5 * time.Minute
	}

	// 修复 SSL 时间字段
	if cfg.SSL.Timeout == 0 {
		cfg.SSL.Timeout = 10 * time.Second
	}

	// 确保用户代理有值
	if cfg.Checker.UserAgent == "" {
		cfg.Checker.UserAgent = "URL-Checker/1.0"
	}
}

func postProcessConfig(cfg *Config) {
	// 根据环境调整配置
	switch cfg.Server.Env {
	case "production":
		// 生产环境强制安全设置
		cfg.Checker.AllowInsecure = false
		cfg.SSL.InsecureSkipVerify = false
		if cfg.Log.Level == "debug" {
			cfg.Log.Level = "info" // 生产环境不建议使用debug
		}
	case "development":
		// 开发环境可以放宽限制
		cfg.Checker.AllowInsecure = true
		cfg.SSL.InsecureSkipVerify = true
	}
}

// GetConfigPath 获取实际使用的配置文件路径
func GetConfigPath() string {
	return viper.ConfigFileUsed()
}
