package worker

import (
	"context"
	"fmt"

	"github.com/yourorg/scanner-worker/internal/config"
	"github.com/yourorg/scanner-worker/internal/db"
	"github.com/yourorg/scanner-worker/internal/s3"
)

// ProcessorConfig holds configuration for a single scan job execution.
// This is the subset of config.Config needed by the scan runner.
type ProcessorConfig struct {
	ScratchDir                 string
	ScannerPath                string
	ScannerTimeoutSeconds      int
	MaxArtifactBytes           int64
	ReportsBucket              string
	WorkerIngestTimeoutSeconds int
	WorkerHeartbeatSeconds     int
}

// Validate checks that all required fields are populated.
func (c ProcessorConfig) Validate() error {
	if c.ScannerPath == "" {
		return fmt.Errorf("ScannerPath is required")
	}
	if c.ReportsBucket == "" {
		return fmt.Errorf("ReportsBucket is required")
	}
	if c.ScratchDir == "" {
		return fmt.Errorf("ScratchDir is required")
	}
	return nil
}

// configFromProcessorConfig creates a config.Config from a ProcessorConfig,
// filling in the fields needed by Runner.processJob(). This bridge allows
// incremental migration without rewriting processJob immediately.
func configFromProcessorConfig(pc ProcessorConfig) config.Config {
	return config.Config{
		ScratchDir:                 pc.ScratchDir,
		ScannerPath:                pc.ScannerPath,
		ScannerTimeoutSeconds:      pc.ScannerTimeoutSeconds,
		MaxArtifactBytes:           pc.MaxArtifactBytes,
		ReportsBucket:              pc.ReportsBucket,
		WorkerIngestTimeoutSeconds: pc.WorkerIngestTimeoutSeconds,
		WorkerHeartbeatSeconds:     pc.WorkerHeartbeatSeconds,
	}
}

// ProcessSingleJob executes a single scan job and returns any error.
// This is the core scan pipeline extracted for use by both the polling
// worker (legacy) and K8s Job runner (new).
func ProcessSingleJob(ctx context.Context, cfg ProcessorConfig, store *db.Store, s3c *s3.Client, workerID string, j *db.Job) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid processor config: %w", err)
	}
	r := &Runner{
		cfg:      configFromProcessorConfig(cfg),
		db:       store,
		s3:       s3c,
		workerID: workerID,
		breaker:  newScannerBreaker(),
	}
	return r.processJob(ctx, j)
}
