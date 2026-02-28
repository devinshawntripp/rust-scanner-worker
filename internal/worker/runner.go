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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/yourorg/scanner-worker/internal/config"
	"github.com/yourorg/scanner-worker/internal/db"
	"github.com/yourorg/scanner-worker/internal/model"
	"github.com/yourorg/scanner-worker/internal/s3"
)

type Runner struct {
	cfg      config.Config
	db       *db.Store
	s3       *s3.Client
	workerID string
}

type scannerSettingsSnapshot struct {
	ModeDefault                  string `json:"mode_default"`
	LightAllowHeuristicFallback  bool   `json:"light_allow_heuristic_fallback"`
	DeepRequireInstalledInventory bool   `json:"deep_require_installed_inventory"`
	NVDEnrichEnabled             bool   `json:"nvd_enrich_enabled"`
	OSVEnrichEnabled             bool   `json:"osv_enrich_enabled"`
	RedHatEnrichEnabled          bool   `json:"redhat_enrich_enabled"`
	EPSSEnrichEnabled            bool   `json:"epss_enrich_enabled"`
	KEVEnrichEnabled             bool   `json:"kev_enrich_enabled"`
	DebianTrackerEnabled         bool   `json:"debian_tracker_enabled"`
	UbuntuTrackerEnabled         bool   `json:"ubuntu_tracker_enabled"`
	AlpineSecDBEnabled           bool   `json:"alpine_secdb_enabled"`
	RedHatUnfixedEnabled         bool   `json:"redhat_unfixed_enabled"`
	SkipCache                    bool   `json:"skip_cache"`
	NVDAPIKey                    string `json:"nvd_api_key"`
	NVDConcurrency               int    `json:"nvd_concurrency"`
	NVDRetryMax                  int    `json:"nvd_retry_max"`
	NVDTimeoutSecs               int    `json:"nvd_timeout_secs"`
	GlobalNVDRatePerMinute       int    `json:"global_nvd_rate_per_minute"`
	OSVBatchSize                 int    `json:"osv_batch_size"`
	OSVTimeoutSecs               int    `json:"osv_timeout_secs"`
	RedHatCVEConcurrency         int    `json:"redhat_cve_concurrency"`
}

func NewRunner(cfg config.Config, store *db.Store, s3c *s3.Client) *Runner {
	return &Runner{
		cfg:      cfg,
		db:       store,
		s3:       s3c,
		workerID: uuid.New().String(),
	}
}

// WorkerID returns the unique identifier for this worker instance.
func (r *Runner) WorkerID() string {
	return r.workerID
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
				ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
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
	log.Printf("job %s: starting (bucket=%s key=%s mode=%s format=%s refs=%v worker=%s)",
		j.ID, j.Bucket, j.ObjectKey, j.Mode, j.Format, j.Refs, r.workerID)
	stopHeartbeat := r.startHeartbeat(j.ID)
	defer stopHeartbeat()

	scratch := filepath.Join(r.cfg.ScratchDir, j.ID)
	_ = os.MkdirAll(scratch, 0o700)
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

	// S3 download with retry (3 attempts, 200ms base delay)
	lastDownloadPct := 1
	lastDownloadMsg := ""
	downloadErr := retry(ctx, 3, 200*time.Millisecond, func() error {
		// Reset progress tracking on each attempt
		lastDownloadPct = 1
		lastDownloadMsg = ""
		return r.s3.DownloadToFile(ctx, j.Bucket, j.ObjectKey, inputPath, func(readBytes int64, totalBytes int64) {
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
		})
	})
	if downloadErr != nil {
		log.Printf("job %s: download error after retries: %v", j.ID, downloadErr)
		return fmt.Errorf("download from s3: %w", downloadErr)
	}
	{
		p := 5
		msg := fmt.Sprintf("s3://%s/%s", j.Bucket, j.ObjectKey)
		_ = r.db.UpdateProgress(ctx, j.ID, p, "s3.download.done")
		_ = r.db.InsertEvent(ctx, j.ID, time.Now(), "s3.download.done", msg, &p)
	}

	// Validate artifact size against configured maximum
	if st, err := os.Stat(inputPath); err == nil {
		if st.Size() > r.cfg.MaxArtifactBytes {
			errMsg := fmt.Sprintf("artifact size %s exceeds maximum allowed %s",
				humanBytes(st.Size()), humanBytes(r.cfg.MaxArtifactBytes))
			log.Printf("job %s: %s", j.ID, errMsg)
			return fmt.Errorf("%s", errMsg)
		}
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

	scanTimeout := time.Duration(r.cfg.ScannerTimeoutSeconds) * time.Second
	scanCtx, scanCancel := context.WithTimeout(ctx, scanTimeout)
	defer scanCancel()

	cmd := exec.CommandContext(scanCtx, r.cfg.ScannerPath, args...)
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
		if scanCtx.Err() == context.DeadlineExceeded {
			log.Printf("job %s: scanner timed out after %s", j.ID, scanTimeout)
			return fmt.Errorf("scanner timed out after %s", scanTimeout)
		}
		log.Printf("job %s: scanner failed: %v", j.ID, scanErr)
		return fmt.Errorf("scanner failed: %w", scanErr)
	}

	// Upload the report with retry (3 attempts, 200ms base delay)
	{
		p := 88
		_ = r.db.UpdateProgress(ctx, j.ID, p, "report.upload.start")
		_ = r.db.InsertEvent(ctx, j.ID, time.Now(), "report.upload.start", "uploading report to S3", &p)
	}
	reportKey := fmt.Sprintf("reports/%s.json", j.ID)
	uploadErr := retry(ctx, 3, 200*time.Millisecond, func() error {
		return r.s3.UploadFile(ctx, r.cfg.ReportsBucket, reportKey, reportPath, "application/json")
	})
	if uploadErr != nil {
		log.Printf("job %s: upload report error after retries: %v", j.ID, uploadErr)
		return fmt.Errorf("upload report: %w", uploadErr)
	}

	// Force final progress update before marking done
	if err := r.db.UpdateProgress(ctx, j.ID, 100, "scan.done"); err != nil {
		log.Printf("job %s: update progress final failed: %v", j.ID, err)
	}

	// Stream-parse the report JSON to keep memory proportional to individual
	// items rather than the entire report.
	report, err := streamParseReport(reportPath)
	if err != nil {
		log.Printf("job %s: failed to parse report json: %v", j.ID, err)
		// Fall back: mark done with empty summary
		dbctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		markErr := r.db.MarkDone(dbctx, j.ID, r.cfg.ReportsBucket, reportKey, []byte(`{}`), nil, nil, nil)
		cancel()
		if markErr != nil {
			log.Printf("job %s: mark done error: %v", j.ID, markErr)
			_ = r.db.MarkFailed(ctx, j.ID, "mark done: "+markErr.Error())
			return markErr
		}
		log.Printf("job %s: completed (parse failed) and marked done (report=%s)", j.ID, reportKey)
		return nil
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

	// Artifact ingest with retry (2 attempts, 200ms base delay)
	{
		p := 92
		_ = r.db.UpdateProgress(ctx, j.ID, p, "ingest.start")
		_ = r.db.InsertEvent(ctx, j.ID, time.Now(), "ingest.start", "writing findings/files/packages to database", &p)
	}
	ingestTimeout := time.Duration(r.cfg.WorkerIngestTimeoutSeconds) * time.Second
	ingestErr := retry(ctx, 2, 200*time.Millisecond, func() error {
		ingestCtx, ingestCancel := context.WithTimeout(context.Background(), ingestTimeout)
		defer ingestCancel()
		return r.db.ReplaceJobArtifacts(ingestCtx, j.ID, report)
	})
	if ingestErr != nil {
		log.Printf("job %s: artifact ingest failed after retries: %v", j.ID, ingestErr)
		_ = r.db.MarkFailed(ctx, j.ID, "artifact ingest: "+ingestErr.Error())
		return ingestErr
	}

	// store only the small summary in SQL, full report stays in object storage
	sumBytes, _ := json.Marshal(report.Summary)
	scanStatus := optionalString(report.ScanStatus)
	inventoryStatus := optionalString(report.InventoryStatus)
	inventoryReason := optionalString(report.InventoryReason)
	dbctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = r.db.MarkDone(
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

// streamParseReport reads a report JSON file using a streaming decoder.
// It parses the top-level fields, and for large arrays (findings, files,
// packages) it decodes items one-at-a-time to keep peak memory proportional
// to a single item rather than the entire array.
func streamParseReport(path string) (*model.ScanReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open report: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)

	// Expect opening '{' of the top-level object
	t, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("read opening token: %w", err)
	}
	if delim, ok := t.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("expected '{', got %v", t)
	}

	report := &model.ScanReport{}

	for dec.More() {
		// Read key name
		t, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("read key: %w", err)
		}
		key, ok := t.(string)
		if !ok {
			return nil, fmt.Errorf("expected string key, got %T", t)
		}

		switch key {
		case "findings":
			findings, err := streamDecodeArray[model.Finding](dec)
			if err != nil {
				return nil, fmt.Errorf("decode findings: %w", err)
			}
			report.Findings = findings

		case "files":
			files, err := streamDecodeArray[model.FileRow](dec)
			if err != nil {
				return nil, fmt.Errorf("decode files: %w", err)
			}
			report.Files = files

		case "packages":
			pkgs, err := streamDecodeArray[model.PackageRow](dec)
			if err != nil {
				return nil, fmt.Errorf("decode packages: %w", err)
			}
			report.Packages = pkgs

		case "summary":
			if err := dec.Decode(&report.Summary); err != nil {
				return nil, fmt.Errorf("decode summary: %w", err)
			}

		case "scan_status":
			if err := dec.Decode(&report.ScanStatus); err != nil {
				return nil, fmt.Errorf("decode scan_status: %w", err)
			}

		case "inventory_status":
			if err := dec.Decode(&report.InventoryStatus); err != nil {
				return nil, fmt.Errorf("decode inventory_status: %w", err)
			}

		case "inventory_reason":
			if err := dec.Decode(&report.InventoryReason); err != nil {
				return nil, fmt.Errorf("decode inventory_reason: %w", err)
			}

		default:
			// Skip unknown fields
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, fmt.Errorf("skip field %q: %w", key, err)
			}
		}
	}

	// Expect closing '}'
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("read closing token: %w", err)
	}

	return report, nil
}

// streamDecodeArray reads a JSON array from a decoder one element at a time,
// so that peak memory is proportional to a single element plus the accumulated
// output slice, rather than requiring the entire array in a raw buffer.
func streamDecodeArray[T any](dec *json.Decoder) ([]T, error) {
	// Expect opening '['
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := t.(json.Delim); !ok || delim != '[' {
		// It might be null
		if t == nil {
			return nil, nil
		}
		return nil, fmt.Errorf("expected '[', got %v", t)
	}

	var result []T
	for dec.More() {
		var item T
		if err := dec.Decode(&item); err != nil {
			return result, err
		}
		result = append(result, item)
	}

	// Consume closing ']'
	if _, err := dec.Token(); err != nil {
		return result, err
	}

	return result, nil
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
		"SCANNER_EPSS_ENRICH=" + boolEnvValue(s.EPSSEnrichEnabled),
		"SCANNER_KEV_ENRICH=" + boolEnvValue(s.KEVEnrichEnabled),
		"SCANNER_DEBIAN_TRACKER_ENRICH=" + boolEnvValue(s.DebianTrackerEnabled),
		"SCANNER_UBUNTU_TRACKER_ENRICH=" + boolEnvValue(s.UbuntuTrackerEnabled),
		"SCANNER_ALPINE_SECDB_ENRICH=" + boolEnvValue(s.AlpineSecDBEnabled),
		// SCANNER_REDHAT_UNFIXED_SKIP is inverted: enabled=true means skip=false
		"SCANNER_REDHAT_UNFIXED_SKIP=" + boolEnvValue(!s.RedHatUnfixedEnabled),
		"SCANNER_SKIP_CACHE=" + boolEnvValue(s.SkipCache),
		"SCANNER_LIGHT_ALLOW_HEURISTIC_FALLBACK=" + boolEnvValue(s.LightAllowHeuristicFallback),
		"SCANNER_DEEP_REQUIRE_INSTALLED_INVENTORY=" + boolEnvValue(s.DeepRequireInstalledInventory),
	}
	if s.NVDAPIKey != "" {
		out = append(out, "NVD_API_KEY="+s.NVDAPIKey)
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
	if s.OSVBatchSize > 0 {
		out = append(out, fmt.Sprintf("SCANNER_OSV_BATCH_SIZE=%d", s.OSVBatchSize))
	}
	if s.OSVTimeoutSecs > 0 {
		out = append(out, fmt.Sprintf("SCANNER_OSV_TIMEOUT_SECS=%d", s.OSVTimeoutSecs))
	}
	if s.RedHatCVEConcurrency > 0 {
		out = append(out, fmt.Sprintf("SCANNER_REDHAT_CVE_CONC=%d", s.RedHatCVEConcurrency))
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

// RecoverStaleJobs re-queues any jobs stuck in 'running' with no recent
// heartbeat. Called once at startup to recover jobs orphaned by crashed workers.
func (r *Runner) RecoverStaleJobs(ctx context.Context) {
	// Use a shorter threshold for startup recovery: 2 minutes without heartbeat
	// indicates the previous worker is gone.
	idleFor := 2 * time.Minute
	ids, err := r.db.RequeueStaleRunning(ctx, idleFor)
	if err != nil {
		log.Printf("startup job recovery failed: %v", err)
		return
	}
	if len(ids) == 0 {
		log.Printf("startup job recovery: no orphaned jobs found")
		return
	}
	for _, id := range ids {
		msg := fmt.Sprintf("re-queued by worker %s at startup (no heartbeat for %s)", r.workerID, idleFor)
		_ = r.db.InsertEvent(ctx, id, time.Now(), "worker.recovery.requeue", msg, nil)
		log.Printf("job %s: re-queued by startup recovery (worker=%s)", id, r.workerID)
	}
	log.Printf("startup job recovery: re-queued %d orphaned jobs", len(ids))
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

		j, err := r.db.AcquireNextQueued(ctx, r.workerID)
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
