package worker

import (
	"context"
	"encoding/json"
	"fmt"
    "log"
    "crypto/sha256"
    "encoding/hex"
    "io"
	"os"
	"os/exec"
	"path/filepath"
    "time"
    "strings"

	"github.com/yourorg/scanner-worker/internal/config"
	"github.com/yourorg/scanner-worker/internal/db"
	"github.com/yourorg/scanner-worker/internal/model"
	"github.com/yourorg/scanner-worker/internal/s3"
)

type Runner struct {
	cfg config.Config
	db  *db.Store
	s3  *s3.Client
}

func NewRunner(cfg config.Config, store *db.Store, s3c *s3.Client) *Runner {
	return &Runner{cfg: cfg, db: store, s3: s3c}
}

func (r *Runner) processJob(ctx context.Context, j *db.Job) error {
    log.Printf("job %s: starting (bucket=%s key=%s mode=%s format=%s refs=%v)", j.ID, j.Bucket, j.ObjectKey, j.Mode, j.Format, j.Refs)
	scratch := filepath.Join(r.cfg.ScratchDir, j.ID)
	_ = os.MkdirAll(scratch, 0o755)
	defer os.RemoveAll(scratch)

    // use original filename to help scanner auto-detect type by extension
    baseName := filepath.Base(j.ObjectKey)
    if baseName == "." || baseName == "/" || baseName == "" { baseName = "input" }
    inputPath := filepath.Join(scratch, baseName)
	progressPath := filepath.Join(scratch, "progress.ndjson")
	reportPath := filepath.Join(scratch, "report.json")

    if err := r.s3.DownloadToFile(ctx, j.Bucket, j.ObjectKey, inputPath); err != nil {
        log.Printf("job %s: download error: %v", j.ID, err)
		return fmt.Errorf("download from s3: %w", err)
	}

    // Inspect downloaded input for debugging differences
    if meta, err := inspectFile(inputPath); err == nil {
        log.Printf("job %s: input size=%dB sha256=%s head=%s", j.ID, meta.Size, meta.SHA256Short, meta.HeadHex)
    }

    // Place global flags before the subcommand (per scanner CLI expectations)
    args := []string{
        "--progress", "--progress-file", progressPath,
        "scan", "--file", inputPath,
        "--format", j.Format, "--out", reportPath,
    }
	if j.Refs {
		args = append(args, "--refs")
	}
	args = append(args, "--mode", j.Mode)

    cmd := exec.CommandContext(ctx, r.cfg.ScannerPath, args...)
    log.Printf("job %s: exec: %s %s", j.ID, r.cfg.ScannerPath, strings.Join(args, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

    stopTail := TailProgress(ctx, r.db, j.ID, progressPath)
	defer stopTail()

    if err := cmd.Start(); err != nil {
        log.Printf("job %s: scanner start error: %v", j.ID, err)
		return fmt.Errorf("start scanner: %w", err)
	}
    if err := cmd.Wait(); err != nil {
        log.Printf("job %s: scanner failed: %v", j.ID, err)
        return fmt.Errorf("scanner failed: %w", err)
	}

	// Upload the report
	reportKey := fmt.Sprintf("reports/%s.json", j.ID)
    if err := r.s3.UploadFile(ctx, r.cfg.ReportsBucket, reportKey, reportPath, "application/json"); err != nil {
        log.Printf("job %s: upload report error: %v", j.ID, err)
		return fmt.Errorf("upload report: %w", err)
	}

    // Force final progress update before marking done
    if err := r.db.UpdateProgress(ctx, j.ID, 100, "scan.done"); err != nil {
        log.Printf("job %s: update progress final failed: %v", j.ID, err)
    }

	// Extract a small summary for DB
	var summary struct {
		Summary model.Summary `json:"summary"`
	}
    if b, err := os.ReadFile(reportPath); err == nil {
        _ = json.Unmarshal(b, &summary)
        // store only the small summary in SQL, full report stays in object storage
        sumBytes, _ := json.Marshal(summary.Summary)
        dbctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        if err := r.db.MarkDone(dbctx, j.ID, r.cfg.ReportsBucket, reportKey, sumBytes); err != nil {
            log.Printf("job %s: mark done error: %v", j.ID, err)
            _ = r.db.MarkFailed(dbctx, j.ID, "mark done: "+err.Error())
            return err
        }
        log.Printf("job %s: completed and marked done (report=%s)", j.ID, reportKey)
        return nil
	}
	// no summary? still mark done with empty summary
    {
        dbctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        if err := r.db.MarkDone(dbctx, j.ID, r.cfg.ReportsBucket, reportKey, []byte(`{}`)); err != nil {
            log.Printf("job %s: mark done error: %v", j.ID, err)
            _ = r.db.MarkFailed(dbctx, j.ID, "mark done: "+err.Error())
            return err
        }
    }
    log.Printf("job %s: completed (no summary) and marked done (report=%s)", j.ID, reportKey)
    return nil
}

type fileMeta struct {
    Size        int64
    SHA256Short string
    HeadHex     string
}

func inspectFile(path string) (*fileMeta, error) {
    f, err := os.Open(path)
    if err != nil { return nil, err }
    defer f.Close()

    h := sha256.New()
    head := make([]byte, 16)
    n, _ := io.ReadFull(f, head)
    if n > 0 { _, _ = h.Write(head[:n]) }
    // hash rest
    if _, err := io.Copy(h, f); err != nil { return nil, err }
    sum := h.Sum(nil)

    st, err := f.Stat()
    if err != nil { return nil, err }

    return &fileMeta{
        Size:        st.Size(),
        SHA256Short: hex.EncodeToString(sum)[:12],
        HeadHex:     hex.EncodeToString(head[:n]),
    }, nil
}

func (r *Runner) RunForever(ctx context.Context) error {
	sem := make(chan struct{}, r.cfg.WorkerConcurrency)
    backoff := time.Millisecond * 500
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

        j, err := r.db.AcquireNextQueued(ctx)
		if err != nil {
            // no queued jobs or transient error; sleep briefly
            time.Sleep(backoff)
            // cap backoff
            if backoff < 5*time.Second { backoff *= 2 } else { backoff = 5*time.Second }
            continue
		}
        backoff = 500 * time.Millisecond

		sem <- struct{}{}
		go func(job *db.Job) {
			defer func() { <-sem }()
            if err := r.processJob(ctx, job); err != nil {
                log.Printf("job %s: failed: %v", job.ID, err)
                _ = r.db.MarkFailed(ctx, job.ID, err.Error())
            }
		}(j)
	}
}
