package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/yourorg/scanner-worker/internal/config"
	"github.com/yourorg/scanner-worker/internal/db"
	"github.com/yourorg/scanner-worker/internal/model"
	"github.com/yourorg/scanner-worker/internal/s3"
)

func main() {
	var (
		batchSize = flag.Int("batch-size", 25, "number of jobs to ingest per batch")
		maxJobs   = flag.Int("max-jobs", 0, "maximum jobs to ingest (0 = unlimited)")
	)
	flag.Parse()

	cfg := config.Load()
	ctx := context.Background()

	store, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	defer store.Pool.Close()

	if err := store.EnsureSchema(ctx); err != nil {
		if isInsufficientPrivilege(err) {
			log.Printf("ensure schema skipped due insufficient privilege: %v", err)
		} else {
			log.Fatalf("ensure schema: %v", err)
		}
	}

	s3c, err := s3.New(cfg.S3Endpoint, cfg.S3AccessKey, cfg.S3SecretKey, cfg.S3UseSSL)
	if err != nil {
		log.Fatalf("s3 client: %v", err)
	}

	tmpRoot := filepath.Join(cfg.ScratchDir, "backfill")
	if err := os.MkdirAll(tmpRoot, 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", tmpRoot, err)
	}

	var total, okCount, failCount int
	for {
		if *maxJobs > 0 && total >= *maxJobs {
			break
		}
		limit := *batchSize
		if limit <= 0 {
			limit = 25
		}
		if *maxJobs > 0 && total+limit > *maxJobs {
			limit = *maxJobs - total
		}

		listCtx, listCancel := context.WithTimeout(ctx, 20*time.Second)
		candidates, err := store.ListBackfillCandidates(listCtx, limit)
		listCancel()
		if err != nil {
			log.Fatalf("list candidates: %v", err)
		}
		if len(candidates) == 0 {
			break
		}

		for _, candidate := range candidates {
			if *maxJobs > 0 && total >= *maxJobs {
				break
			}
			total++
			if err := ingestOne(ctx, store, s3c, tmpRoot, &candidate); err != nil {
				failCount++
				log.Printf("backfill job %s failed: %v", candidate.ID, err)
				continue
			}
			okCount++
		}
	}

	log.Printf("backfill complete: processed=%d ok=%d failed=%d", total, okCount, failCount)
}

func ingestOne(ctx context.Context, store *db.Store, s3c *s3.Client, tmpRoot string, candidate *db.BackfillJob) error {
	tmpFile := filepath.Join(tmpRoot, candidate.ID+".report.json")
	defer os.Remove(tmpFile)

	dlCtx, dlCancel := context.WithTimeout(ctx, 8*time.Minute)
	err := s3c.DownloadToFile(dlCtx, candidate.ReportBucket, candidate.ReportKey, tmpFile, nil)
	dlCancel()
	if err != nil {
		return err
	}

	raw, err := os.ReadFile(tmpFile)
	if err != nil {
		return err
	}

	var report model.ScanReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return err
	}

	if len(report.Files) == 0 {
		baseName := filepath.Base(candidate.ObjectKey)
		if baseName == "" || baseName == "." || baseName == "/" {
			baseName = "artifact"
		}
		report.Files = append(report.Files, model.FileRow{
			Path:       baseName,
			EntryType:  "file",
			ParentPath: "",
		})
	}

	ingestCtx, ingestCancel := context.WithTimeout(ctx, 2*time.Minute)
	err = store.ReplaceJobArtifacts(ingestCtx, candidate.ID, &report)
	ingestCancel()
	if err != nil {
		return err
	}

	summaryJSON, _ := json.Marshal(report.Summary)
	doneCtx, doneCancel := context.WithTimeout(ctx, 20*time.Second)
	err = store.MarkDone(
		doneCtx,
		candidate.ID,
		candidate.ReportBucket,
		candidate.ReportKey,
		summaryJSON,
		optionalString(report.ScanStatus),
		optionalString(report.InventoryStatus),
		optionalString(report.InventoryReason),
	)
	doneCancel()
	if err != nil {
		return err
	}

	log.Printf("backfill job %s ingested (findings=%d files=%d)", candidate.ID, len(report.Findings), len(report.Files))
	return nil
}

func optionalString(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func isInsufficientPrivilege(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42501"
}
