package worker

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
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
func (r *Runner) generateSbomExports(ctx context.Context, jobID, reportPath, reportBucket, reportKey string) {
	formats := []struct {
		name string
		ext  string
	}{
		{"cyclonedx", "sbom.cdx.json"},
		{"spdx", "sbom.spdx.json"},
		{"syft", "sbom.syft.json"},
	}

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
	}
}

