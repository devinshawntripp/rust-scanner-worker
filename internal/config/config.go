package config

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	DatabaseURL            string
	S3Endpoint             string
	S3AccessKey            string
	S3SecretKey            string
	S3UseSSL               bool
	S3Region               string
	UploadsBucket          string
	ReportsBucket          string
	ScratchDir             string
	ScannerPath            string
	WorkerConcurrency      int
	StaleJobTimeoutSeconds int
	StaleSweepSeconds      int
	WorkerHeartbeatSeconds    int
	ScannerTimeoutSeconds     int
	MaxArtifactBytes          int64
	WorkerIngestTimeoutSeconds int
	HTTPAddr                  string
}

func getBool(key, def string) bool {
	v := os.Getenv(key)
	if v == "" {
		v = def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}

func getInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func getInt64(key string, def int64) int64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func Load() Config {
	cfg := Config{
		DatabaseURL:            os.Getenv("DATABASE_URL"),
		S3Endpoint:             os.Getenv("S3_ENDPOINT"),
		S3AccessKey:            os.Getenv("S3_ACCESS_KEY"),
		S3SecretKey:            os.Getenv("S3_SECRET_KEY"),
		S3UseSSL:               getBool("S3_USE_SSL", "false"),
		S3Region:               os.Getenv("S3_REGION"),
		UploadsBucket:          os.Getenv("UPLOADS_BUCKET"),
		ReportsBucket:          os.Getenv("REPORTS_BUCKET"),
		ScratchDir:             os.Getenv("SCRATCH_DIR"),
		ScannerPath:            os.Getenv("SCANNER_PATH"),
		WorkerConcurrency:      getInt("WORKER_CONCURRENCY", 2),
		StaleJobTimeoutSeconds: getInt("WORKER_STALE_JOB_TIMEOUT_SECONDS", 1800),
		StaleSweepSeconds:      getInt("WORKER_STALE_SWEEP_SECONDS", 60),
		WorkerHeartbeatSeconds:     getInt("WORKER_HEARTBEAT_SECONDS", 60),
		ScannerTimeoutSeconds:     getInt("SCANNER_TIMEOUT_SECONDS", 1800),
		MaxArtifactBytes:          getInt64("MAX_ARTIFACT_BYTES", 10737418240),
		WorkerIngestTimeoutSeconds: getInt("WORKER_INGEST_TIMEOUT_SECONDS", 300),
		HTTPAddr:                  os.Getenv("HTTP_ADDR"),
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
	if cfg.StaleJobTimeoutSeconds <= 0 {
		cfg.StaleJobTimeoutSeconds = 1800
	}
	if cfg.StaleSweepSeconds <= 0 {
		cfg.StaleSweepSeconds = 60
	}
	if cfg.WorkerHeartbeatSeconds <= 0 {
		cfg.WorkerHeartbeatSeconds = 60
	}
	if cfg.ScannerTimeoutSeconds <= 0 {
		cfg.ScannerTimeoutSeconds = 1800
	}
	if cfg.MaxArtifactBytes <= 0 {
		cfg.MaxArtifactBytes = 10737418240 // 10 GiB
	}
	if cfg.WorkerIngestTimeoutSeconds <= 0 {
		cfg.WorkerIngestTimeoutSeconds = 300
	}
	if cfg.UploadsBucket == "" || cfg.ReportsBucket == "" {
		log.Fatal("UPLOADS_BUCKET and REPORTS_BUCKET are required")
	}
	// Validate SCANNER_PATH: must be absolute and executable
	if !filepath.IsAbs(cfg.ScannerPath) {
		log.Fatalf("SCANNER_PATH must be an absolute path, got: %q", cfg.ScannerPath)
	}
	if info, err := os.Stat(cfg.ScannerPath); err != nil {
		log.Fatalf("SCANNER_PATH %q not found: %v", cfg.ScannerPath, err)
	} else if info.IsDir() {
		log.Fatalf("SCANNER_PATH %q is a directory, not an executable", cfg.ScannerPath)
	} else if info.Mode()&0o111 == 0 {
		log.Fatalf("SCANNER_PATH %q is not executable", cfg.ScannerPath)
	}
	return cfg
}
