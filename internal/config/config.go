package config

import (
    "time"
    "github.com/spf13/viper"
)

type Config struct {
    Server struct {
        Port         string        `mapstructure:"port"`
        ReadTimeout  time.Duration `mapstructure:"read_timeout"`
        WriteTimeout time.Duration `mapstructure:"write_timeout"`
    } `mapstructure:"server"`
    
    Checker struct {
        MaxConcurrent int           `mapstructure:"max_concurrent"`
        Timeout       time.Duration `mapstructure:"timeout"`
        MaxRetries    int           `mapstructure:"max_retries"`
    } `mapstructure:"checker"`
    
    SSL struct {
        CheckEnabled bool `mapstructure:"check_enabled"`
    } `mapstructure:"ssl"`
}

func Load() (*Config, error) {
    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath("./configs")
    viper.AddConfigPath(".")
    
    // 设置默认值
    viper.SetDefault("server.port", "8080")
    viper.SetDefault("server.read_timeout", "30s")
    viper.SetDefault("server.write_timeout", "30s")
    viper.SetDefault("checker.max_concurrent", 10)
    viper.SetDefault("checker.timeout", "10s")
    viper.SetDefault("checker.max_retries", 3)
    viper.SetDefault("ssl.check_enabled", true)
    
    // 读取环境变量
    viper.AutomaticEnv()
    
    if err := viper.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
            return nil, err
        }
    }
    
    var cfg Config
    if err := viper.Unmarshal(&cfg); err != nil {
        return nil, err
    }
    
    return &cfg, nil
}
