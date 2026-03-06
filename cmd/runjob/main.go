package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"os/signal"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/yourorg/scanner-worker/internal/config"
	"github.com/yourorg/scanner-worker/internal/db"
	s3c "github.com/yourorg/scanner-worker/internal/s3"
	"github.com/yourorg/scanner-worker/internal/worker"
)

func main() {
	_ = godotenv.Load(".env.local")
	_ = godotenv.Load(".env")

	jobID := os.Getenv("SCAN_JOB_ID")
	if jobID == "" {
		log.Fatal("SCAN_JOB_ID is required")
	}

	cfg := config.Load()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	store, err := db.Open(ctx, cfg.DatabaseURL, 1)
	if err != nil {
		log.Fatal(err)
	}
	if err := store.Ping(ctx); err != nil {
		log.Fatal(err)
	}

	s3, err := s3c.New(cfg.S3Endpoint, cfg.S3AccessKey, cfg.S3SecretKey, cfg.S3UseSSL)
	if err != nil {
		log.Fatal(err)
	}

	// Print scanner version
	cmd := exec.CommandContext(ctx, cfg.ScannerPath, "--version")
	out, _ := cmd.CombinedOutput()
	if len(out) > 0 {
		log.Printf("scanrook version: %s", string(out))
	}

	job, err := store.GetJob(ctx, jobID)
	if err != nil {
		log.Fatalf("failed to fetch job %s: %v", jobID, err)
	}

	workerID := uuid.New().String()
	log.Printf("runjob: starting job=%s worker=%s", jobID, workerID)

	pcfg := worker.ProcessorConfig{
		ScratchDir:                 cfg.ScratchDir,
		ScannerPath:                cfg.ScannerPath,
		ScannerTimeoutSeconds:      cfg.ScannerTimeoutSeconds,
		MaxArtifactBytes:           cfg.MaxArtifactBytes,
		ReportsBucket:              cfg.ReportsBucket,
		WorkerIngestTimeoutSeconds: cfg.WorkerIngestTimeoutSeconds,
		WorkerHeartbeatSeconds:     cfg.WorkerHeartbeatSeconds,
	}

	if err := worker.ProcessSingleJob(ctx, pcfg, store, s3, workerID, job); err != nil {
		log.Printf("runjob: job %s failed: %v", jobID, err)
		_ = store.MarkFailed(ctx, jobID, err.Error())
		os.Exit(1)
	}

	log.Printf("runjob: job %s completed successfully", jobID)
}
