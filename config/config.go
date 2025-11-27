package config

import "embed"

const (
	ymlExtension = ".yaml"
)

//go:embed *.yaml
var cfgFiles embed.FS

type (
	Config struct {
		Scope            string               `yaml:"scope"`
		LogLevel         string               `yaml:"log-level"`
		DbCfg            *DatabaseConfig      `yaml:"data_base"`
		ObjectStorageCfg *ObjectStorageConfig `yaml:"object_storage"`
	}

	DatabaseConfig struct {
		Mock bool   `yaml:"mock"`
		Path string `yaml:"path"`
	}

	ObjectStorageConfig struct {
		BasePath string    `yaml:"base-path"`
		Mock     bool      `yaml:"mock"`
		S3       *S3Config `yaml:"s3"`
	}

	S3Config struct {
		Bucket         string `yaml:"bucket"`
		Region         string `yaml:"region"`
		Endpoint       string `yaml:"endpoint"`
		ForcePathStyle bool   `yaml:"force-path-style"`
	}
)
