package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// isSbomFile checks if a file is an SBOM (CycloneDX, SPDX, or Syft JSON)
// by reading the first 4KB and looking for format-specific keys.
func isSbomFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 4096)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return false
	}
	buf = buf[:n]

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(buf, &obj); err != nil {
		if err := json.Unmarshal(append(buf, '}'), &obj); err != nil {
			return false
		}
	}

	if _, ok := obj["bomFormat"]; ok {
		return true
	}
	if _, ok := obj["spdxVersion"]; ok {
		return true
	}
	if _, ok := obj["artifacts"]; ok {
		return true
	}
	return false
}

// generateSbomExports runs `scanrook sbom export` for all three formats
// and uploads the results to S3. This is non-blocking — scan is already marked done.
// Returns the number of successfully exported formats (0-3).
func (r *Runner) generateSbomExports(ctx context.Context, jobID, reportPath, reportBucket, reportKey string) int {
	formats := []struct {
		name string
		ext  string
	}{
		{"cyclonedx", "sbom.cdx.json"},
		{"spdx", "sbom.spdx.json"},
		{"syft", "sbom.syft.json"},
	}

	success := 0
	for _, f := range formats {
		outPath := reportPath + "." + f.ext
		cmd := exec.CommandContext(ctx, r.cfg.ScannerPath,
			"sbom", "export",
			"--report", reportPath,
			"--sbom-format", f.name,
			"--out", outPath,
		)
		cmd.Env = os.Environ()

		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[job=%s] sbom export %s failed: %v: %s", jobID, f.name, err, string(output))
			continue
		}

		sbomKey := strings.TrimSuffix(reportKey, ".json") + "." + f.ext
		if err := r.s3.UploadFile(ctx, reportBucket, sbomKey, outPath, "application/json"); err != nil {
			log.Printf("[job=%s] sbom upload %s failed: %v", jobID, f.name, err)
			continue
		}

		log.Printf("[job=%s] sbom export %s uploaded to %s/%s", jobID, f.name, reportBucket, sbomKey)
		os.Remove(outPath)
		success++
	}
	return success
}

// generateSbomDiff finds the previous scan of the same file in the same org,
// downloads its report, runs `scanrook sbom diff`, uploads the diff JSON to S3,
// and stores the summary on the job row.
func (r *Runner) generateSbomDiff(ctx context.Context, jobID, orgID, objectKey, currentReportPath, reportBucket, reportKey string) {
	prev, err := r.db.FindPreviousDoneJob(ctx, jobID, orgID, objectKey)
	if err != nil {
		log.Printf("[job=%s] sbom diff: failed to find previous job: %v", jobID, err)
		return
	}
	if prev == nil || prev.ReportBucket == nil || prev.ReportKey == nil {
		log.Printf("[job=%s] sbom diff: no previous scan to compare against", jobID)
		return
	}

	// Download the baseline report from S3
	baselineDir := filepath.Join(os.TempDir(), fmt.Sprintf("sbom-diff-%s", jobID))
	if err := os.MkdirAll(baselineDir, 0o755); err != nil {
		log.Printf("[job=%s] sbom diff: mkdir failed: %v", jobID, err)
		return
	}
	defer os.RemoveAll(baselineDir)

	baselinePath := filepath.Join(baselineDir, "baseline.json")
	if err := r.s3.DownloadToFile(ctx, *prev.ReportBucket, *prev.ReportKey, baselinePath, nil); err != nil {
		log.Printf("[job=%s] sbom diff: failed to download baseline report: %v", jobID, err)
		return
	}

	// Run scanrook sbom diff
	diffPath := filepath.Join(baselineDir, "diff.json")
	cmd := exec.CommandContext(ctx, r.cfg.ScannerPath,
		"sbom", "diff",
		"--baseline", baselinePath,
		"--current", currentReportPath,
		"--json",
		"--out", diffPath,
	)
	cmd.Env = os.Environ()

	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[job=%s] sbom diff: scanner diff failed: %v: %s", jobID, err, string(output))
		return
	}

	// Read and parse diff to extract summary
	diffBytes, err := os.ReadFile(diffPath)
	if err != nil {
		log.Printf("[job=%s] sbom diff: failed to read diff output: %v", jobID, err)
		return
	}

	// Extract summary counts from the diff JSON
	var diffData map[string]json.RawMessage
	if err := json.Unmarshal(diffBytes, &diffData); err != nil {
		log.Printf("[job=%s] sbom diff: failed to parse diff JSON: %v", jobID, err)
		return
	}

	// Build summary: count added/removed/changed from top-level arrays
	summary := buildDiffSummary(diffData)
	summaryBytes, _ := json.Marshal(summary)

	// Store summary on the job row
	if err := r.db.UpdateSbomDiffSummary(ctx, jobID, summaryBytes); err != nil {
		log.Printf("[job=%s] sbom diff: failed to store summary: %v", jobID, err)
		return
	}

	// Upload full diff JSON to S3
	diffKey := strings.TrimSuffix(reportKey, ".json") + ".sbom-diff.json"
	if err := r.s3.UploadFile(ctx, reportBucket, diffKey, diffPath, "application/json"); err != nil {
		log.Printf("[job=%s] sbom diff: failed to upload diff: %v", jobID, err)
		return
	}

	log.Printf("[job=%s] sbom diff: uploaded to %s/%s (added=%d, removed=%d, changed=%d)",
		jobID, reportBucket, diffKey, summary.Added, summary.Removed, summary.Changed)

	// Emit SSE event
	p := 100
	msg := fmt.Sprintf("SBOM diff complete: +%d -%d ~%d", summary.Added, summary.Removed, summary.Changed)
	if err := r.db.InsertEvent(ctx, jobID, time.Now(), "sbom_diff_complete", msg, &p); err != nil {
		log.Printf("[job=%s] sbom diff: failed to insert event: %v", jobID, err)
	}
}

type diffSummary struct {
	Added   int `json:"added"`
	Removed int `json:"removed"`
	Changed int `json:"changed"`
}

// buildDiffSummary extracts counts from the diff JSON. The scanner's diff output
// has "added", "removed", and "changed" arrays at the top level.
func buildDiffSummary(data map[string]json.RawMessage) diffSummary {
	s := diffSummary{}
	if v, ok := data["added"]; ok {
		var arr []json.RawMessage
		if json.Unmarshal(v, &arr) == nil {
			s.Added = len(arr)
		}
	}
	if v, ok := data["removed"]; ok {
		var arr []json.RawMessage
		if json.Unmarshal(v, &arr) == nil {
			s.Removed = len(arr)
		}
	}
	if v, ok := data["changed"]; ok {
		var arr []json.RawMessage
		if json.Unmarshal(v, &arr) == nil {
			s.Changed = len(arr)
		}
	}
	return s
}

