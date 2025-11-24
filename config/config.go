package config

import "embed"

const (
	ymlExtension = ".yml"
)

var cfgFiles embed.FS

type (
	Config struct {
		Scope    string               `yaml:"scope"`
		LogLevel string               `yaml:"log-level"`
		DbCfg            *DatabaseConfig      `yaml:"data_base"`
		ObjectStorageCfg *ObjectStorageConfig `yaml:"object_storage"`
	}

	DatabaseConfig struct {
		Mock bool `yaml:"mock"`
	}

	ObjectStorageConfig struct {
		BasePath string `yaml:"base-path"`
		Mock     bool   `yaml:"mock"`
	}
)
