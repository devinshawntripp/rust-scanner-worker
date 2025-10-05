package config

import (
	"log"
	"os"
	"strconv"
)

type Config struct {
	DatabaseURL     string
	S3Endpoint      string
	S3AccessKey     string
	S3SecretKey     string
	S3UseSSL        bool
	S3Region        string
	UploadsBucket   string
	ReportsBucket   string
	ScratchDir      string
	ScannerPath     string
	WorkerConcurrency int
	HTTPAddr        string
}

func getBool(key, def string) bool {
	v := os.Getenv(key)
	if v == "" {
		v = def
	}
	b, err := strconv.ParseBool(v)
	if err != nil { return false }
	return b
}

func getInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" { return def }
	n, err := strconv.Atoi(v)
	if err != nil { return def }
	return n
}

func Load() Config {
	cfg := Config{
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		S3Endpoint:       os.Getenv("S3_ENDPOINT"),
		S3AccessKey:      os.Getenv("S3_ACCESS_KEY"),
		S3SecretKey:      os.Getenv("S3_SECRET_KEY"),
		S3UseSSL:         getBool("S3_USE_SSL", "false"),
		S3Region:         os.Getenv("S3_REGION"),
		UploadsBucket:    os.Getenv("UPLOADS_BUCKET"),
		ReportsBucket:    os.Getenv("REPORTS_BUCKET"),
		ScratchDir:       os.Getenv("SCRATCH_DIR"),
		ScannerPath:      os.Getenv("SCANNER_PATH"),
		WorkerConcurrency: getInt("WORKER_CONCURRENCY", 2),
		HTTPAddr:         os.Getenv("HTTP_ADDR"),
	}
	// quick sanity
	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	if cfg.ScratchDir == "" {
		cfg.ScratchDir = "/scratch"
	}
	if cfg.ScannerPath == "" {
		cfg.ScannerPath = "/usr/local/bin/scanner"
	}
	if cfg.UploadsBucket == "" || cfg.ReportsBucket == "" {
		log.Fatal("UPLOADS_BUCKET and REPORTS_BUCKET are required")
	}
	return cfg
}
