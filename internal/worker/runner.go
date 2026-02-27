package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
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

type scannerSettingsSnapshot struct {
	ModeDefault                   string `json:"mode_default"`
	LightAllowHeuristicFallback   bool   `json:"light_allow_heuristic_fallback"`
	DeepRequireInstalledInventory bool   `json:"deep_require_installed_inventory"`
	NVDEnrichEnabled              bool   `json:"nvd_enrich_enabled"`
	OSVEnrichEnabled              bool   `json:"osv_enrich_enabled"`
	RedHatEnrichEnabled           bool   `json:"redhat_enrich_enabled"`
	SkipCache                     bool   `json:"skip_cache"`
	NVDConcurrency                int    `json:"nvd_concurrency"`
	NVDRetryMax                   int    `json:"nvd_retry_max"`
	NVDTimeoutSecs                int    `json:"nvd_timeout_secs"`
	GlobalNVDRatePerMinute        int    `json:"global_nvd_rate_per_minute"`
}

func NewRunner(cfg config.Config, store *db.Store, s3c *s3.Client) *Runner {
	return &Runner{cfg: cfg, db: store, s3: s3c}
}

func (r *Runner) startHeartbeat(jobID string) (stop func()) {
	interval := time.Duration(r.cfg.WorkerHeartbeatSeconds) * time.Second
	if interval <= 0 {
		return func() {}
	}
	done := make(chan struct{})
	hbCtx, cancel := context.WithCancel(context.Background())
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-ticker.C:
				msg := fmt.Sprintf("job %s still running", jobID)
				ctx, c := context.WithTimeout(context.Background(), 2*time.Second)
				_ = r.db.InsertEvent(ctx, jobID, time.Now(), "worker.heartbeat", msg, nil)
				c()
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func (r *Runner) processJob(ctx context.Context, j *db.Job) error {
	log.Printf("job %s: starting (bucket=%s key=%s mode=%s format=%s refs=%v)", j.ID, j.Bucket, j.ObjectKey, j.Mode, j.Format, j.Refs)
	stopHeartbeat := r.startHeartbeat(j.ID)
	defer stopHeartbeat()

	scratch := filepath.Join(r.cfg.ScratchDir, j.ID)
	_ = os.MkdirAll(scratch, 0o755)
	defer os.RemoveAll(scratch)

	// use original filename to help scanner auto-detect type by extension
	baseName := filepath.Base(j.ObjectKey)
	if baseName == "." || baseName == "/" || baseName == "" {
		baseName = "input"
	}
	inputPath := filepath.Join(scratch, baseName)
	progressPath := filepath.Join(scratch, "progress.ndjson")
	reportPath := filepath.Join(scratch, "report.json")

	// Emit early worker-side progress so large object downloads are visible in UI.
	{
		p := 1
		msg := fmt.Sprintf("s3://%s/%s", j.Bucket, j.ObjectKey)
		_ = r.db.UpdateProgress(ctx, j.ID, p, "s3.download.start")
		_ = r.db.InsertEvent(ctx, j.ID, time.Now(), "s3.download.start", msg, &p)
	}
	lastDownloadPct := 1
	lastDownloadMsg := ""
	if err := r.s3.DownloadToFile(ctx, j.Bucket, j.ObjectKey, inputPath, func(readBytes int64, totalBytes int64) {
		msg := downloadProgressDetail(j.Bucket, j.ObjectKey, readBytes, totalBytes)
		p := downloadPct(readBytes, totalBytes)
		if p <= lastDownloadPct && msg == lastDownloadMsg {
			return
		}
		if p < lastDownloadPct {
			p = lastDownloadPct
		}
		lastDownloadPct = p
		lastDownloadMsg = msg
		_ = r.db.UpdateProgress(ctx, j.ID, p, "s3.download.progress")
		_ = r.db.InsertEvent(ctx, j.ID, time.Now(), "s3.download.progress", msg, &p)
	}); err != nil {
		log.Printf("job %s: download error: %v", j.ID, err)
		return fmt.Errorf("download from s3: %w", err)
	}
	{
		p := 5
		msg := fmt.Sprintf("s3://%s/%s", j.Bucket, j.ObjectKey)
		_ = r.db.UpdateProgress(ctx, j.ID, p, "s3.download.done")
		_ = r.db.InsertEvent(ctx, j.ID, time.Now(), "s3.download.done", msg, &p)
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
	// Platform scans should retain full file tree output for Files API/UI.
	baseEnv := append(os.Environ(), "SCANNER_INCLUDE_FILE_TREE=1")
	cmd.Env = append(baseEnv, buildScannerEnvFromSettings(j.SettingsJSON, j.Mode)...)
	log.Printf("job %s: exec: %s %s", j.ID, r.cfg.ScannerPath, strings.Join(args, " "))
	var scannerStdout, scannerStderr strings.Builder
	cmd.Stdout = &scannerStdout
	cmd.Stderr = &scannerStderr

	{
		p := 8
		_ = r.db.UpdateProgress(ctx, j.ID, p, "scanner.start")
		_ = r.db.InsertEvent(ctx, j.ID, time.Now(), "scanner.start", r.cfg.ScannerPath, &p)
	}
	stopTail := TailProgress(ctx, r.db, j.ID, progressPath)
	defer stopTail()

	if err := cmd.Start(); err != nil {
		log.Printf("job %s: scanner start error: %v", j.ID, err)
		return fmt.Errorf("start scanner: %w", err)
	}
	scanErr := cmd.Wait()
	if s := strings.TrimSpace(scannerStdout.String()); s != "" {
		log.Printf("job %s: scanner stdout: %s", j.ID, s)
	}
	if s := strings.TrimSpace(scannerStderr.String()); s != "" {
		log.Printf("job %s: scanner stderr: %s", j.ID, s)
	}
	if scanErr != nil {
		log.Printf("job %s: scanner failed: %v", j.ID, scanErr)
		return fmt.Errorf("scanner failed: %w", scanErr)
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

	// Extract summary + normalized artifacts for DB-backed findings/files APIs.
	if b, err := os.ReadFile(reportPath); err == nil {
		var report model.ScanReport
		if err := json.Unmarshal(b, &report); err != nil {
			log.Printf("job %s: failed to parse report json: %v", j.ID, err)
		}

		if len(report.Files) == 0 {
			if st, err := os.Stat(inputPath); err == nil {
				size := st.Size()
				report.Files = append(report.Files, model.FileRow{
					Path:       baseName,
					EntryType:  "file",
					SizeBytes:  &size,
					ParentPath: "",
				})
			}
		}

		ingestCtx, ingestCancel := context.WithTimeout(context.Background(), 90*time.Second)
		if err := r.db.ReplaceJobArtifacts(ingestCtx, j.ID, &report); err != nil {
			ingestCancel()
			log.Printf("job %s: artifact ingest failed: %v", j.ID, err)
			_ = r.db.MarkFailed(ctx, j.ID, "artifact ingest: "+err.Error())
			return err
		}
		ingestCancel()

		// store only the small summary in SQL, full report stays in object storage
		sumBytes, _ := json.Marshal(report.Summary)
		scanStatus := optionalString(report.ScanStatus)
		inventoryStatus := optionalString(report.InventoryStatus)
		inventoryReason := optionalString(report.InventoryReason)
		dbctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := r.db.MarkDone(
			dbctx,
			j.ID,
			r.cfg.ReportsBucket,
			reportKey,
			sumBytes,
			scanStatus,
			inventoryStatus,
			inventoryReason,
		)
		cancel()
		if err != nil {
			log.Printf("job %s: mark done error: %v", j.ID, err)
			_ = r.db.MarkFailed(ctx, j.ID, "mark done: "+err.Error())
			return err
		}
		log.Printf("job %s: completed and marked done (report=%s)", j.ID, reportKey)
		return nil
	}
	// no summary? still mark done with empty summary
	{
		dbctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := r.db.MarkDone(dbctx, j.ID, r.cfg.ReportsBucket, reportKey, []byte(`{}`), nil, nil, nil)
		cancel()
		if err != nil {
			log.Printf("job %s: mark done error: %v", j.ID, err)
			_ = r.db.MarkFailed(ctx, j.ID, "mark done: "+err.Error())
			return err
		}
	}
	log.Printf("job %s: completed (no summary) and marked done (report=%s)", j.ID, reportKey)
	return nil
}

func optionalString(v string) *string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return &v
}

func boolEnvValue(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func buildScannerEnvFromSettings(raw []byte, mode string) []string {
	if len(raw) == 0 {
		return nil
	}

	var s scannerSettingsSnapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}

	out := []string{
		"SCANNER_NVD_ENRICH=" + boolEnvValue(s.NVDEnrichEnabled),
		"SCANNER_OSV_ENRICH=" + boolEnvValue(s.OSVEnrichEnabled),
		"SCANNER_REDHAT_ENRICH=" + boolEnvValue(s.RedHatEnrichEnabled),
		"SCANNER_SKIP_CACHE=" + boolEnvValue(s.SkipCache),
		"SCANNER_LIGHT_ALLOW_HEURISTIC_FALLBACK=" + boolEnvValue(s.LightAllowHeuristicFallback),
		"SCANNER_DEEP_REQUIRE_INSTALLED_INVENTORY=" + boolEnvValue(s.DeepRequireInstalledInventory),
	}
	if s.NVDConcurrency > 0 {
		out = append(out, fmt.Sprintf("SCANNER_NVD_CONC=%d", s.NVDConcurrency))
	}
	if s.NVDRetryMax > 0 {
		out = append(out, fmt.Sprintf("SCANNER_NVD_RETRY_MAX=%d", s.NVDRetryMax))
	}
	if s.NVDTimeoutSecs > 0 {
		out = append(out, fmt.Sprintf("SCANNER_NVD_TIMEOUT_SECS=%d", s.NVDTimeoutSecs))
	}
	if s.GlobalNVDRatePerMinute > 0 {
		out = append(out, fmt.Sprintf("SCANNER_NVD_GLOBAL_RATE_PER_MINUTE=%d", s.GlobalNVDRatePerMinute))
	}

	normalizedMode := strings.ToLower(strings.TrimSpace(mode))
	if normalizedMode == "deep" {
		out = append(out, "SCANNER_SCAN_MODE=deep")
	} else if normalizedMode == "light" {
		out = append(out, "SCANNER_SCAN_MODE=light")
	}

	return out
}

func downloadPct(readBytes, totalBytes int64) int {
	if totalBytes <= 0 {
		return 3
	}
	if readBytes < 0 {
		readBytes = 0
	}
	if readBytes > totalBytes {
		readBytes = totalBytes
	}
	frac := float64(readBytes) / float64(totalBytes)
	p := 1 + int(math.Ceil(frac*4.0))
	if p < 1 {
		return 1
	}
	if p > 5 {
		return 5
	}
	return p
}

func humanBytes(n int64) string {
	if n < 0 {
		n = 0
	}
	const unit = 1024.0
	if n < 1024 {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := unit, 0
	for v := float64(n) / unit; v >= unit && exp < 5; v /= unit {
		div *= unit
		exp++
	}
	value := float64(n) / div
	suffixes := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	return fmt.Sprintf("%.1f%s", value, suffixes[exp])
}

func downloadProgressDetail(bucket, key string, readBytes, totalBytes int64) string {
	if totalBytes > 0 {
		pct := (float64(readBytes) / float64(totalBytes)) * 100.0
		if pct < 0 {
			pct = 0
		}
		if pct > 100 {
			pct = 100
		}
		return fmt.Sprintf(
			"s3://%s/%s %.1f%% (%s/%s)",
			bucket,
			key,
			pct,
			humanBytes(readBytes),
			humanBytes(totalBytes),
		)
	}
	return fmt.Sprintf("s3://%s/%s %s", bucket, key, humanBytes(readBytes))
}

type fileMeta struct {
	Size        int64
	SHA256Short string
	HeadHex     string
}

func inspectFile(path string) (*fileMeta, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	head := make([]byte, 16)
	n, _ := io.ReadFull(f, head)
	if n > 0 {
		_, _ = h.Write(head[:n])
	}
	// hash rest
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	sum := h.Sum(nil)

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}

	return &fileMeta{
		Size:        st.Size(),
		SHA256Short: hex.EncodeToString(sum)[:12],
		HeadHex:     hex.EncodeToString(head[:n]),
	}, nil
}

func (r *Runner) reapStaleRunning(ctx context.Context) {
	idleFor := time.Duration(r.cfg.StaleJobTimeoutSeconds) * time.Second
	if idleFor <= 0 {
		return
	}
	ids, err := r.db.FailStaleRunning(ctx, idleFor)
	if err != nil {
		log.Printf("stale sweep failed: %v", err)
		return
	}
	if len(ids) == 0 {
		return
	}
	for _, id := range ids {
		msg := fmt.Sprintf("no progress heartbeat for %s", idleFor.Round(time.Second))
		_ = r.db.InsertEvent(ctx, id, time.Now(), "worker.stale.fail", msg, nil)
		log.Printf("job %s: marked failed by stale sweep (%s)", id, idleFor.Round(time.Second))
	}
}

func (r *Runner) RunForever(ctx context.Context) error {
	sem := make(chan struct{}, r.cfg.WorkerConcurrency)
	backoff := time.Millisecond * 500
	sweepEvery := time.Duration(r.cfg.StaleSweepSeconds) * time.Second
	nextSweep := time.Now()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if sweepEvery > 0 && time.Now().After(nextSweep) {
			r.reapStaleRunning(ctx)
			nextSweep = time.Now().Add(sweepEvery)
		}

		j, err := r.db.AcquireNextQueued(ctx)
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				log.Printf("acquire queued job failed: %v", err)
			}
			// no queued jobs or transient error; sleep briefly
			time.Sleep(backoff)
			// cap backoff
			if backoff < 5*time.Second {
				backoff *= 2
			} else {
				backoff = 5 * time.Second
			}
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
