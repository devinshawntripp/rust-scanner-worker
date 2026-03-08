package worker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsSbomFile_CycloneDX(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.cdx.json")
	os.WriteFile(p, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`), 0644)
	if !isSbomFile(p) {
		t.Fatal("expected CycloneDX to be detected as SBOM")
	}
}

func TestIsSbomFile_SPDX(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.spdx.json")
	os.WriteFile(p, []byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`), 0644)
	if !isSbomFile(p) {
		t.Fatal("expected SPDX to be detected as SBOM")
	}
}

func TestIsSbomFile_Syft(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.syft.json")
	os.WriteFile(p, []byte(`{"artifacts":[],"source":{"type":"image"}}`), 0644)
	if !isSbomFile(p) {
		t.Fatal("expected Syft to be detected as SBOM")
	}
}

func TestIsSbomFile_NotSbom(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "regular.tar")
	os.WriteFile(p, []byte{0x1f, 0x8b, 0x08}, 0644)
	if isSbomFile(p) {
		t.Fatal("expected non-SBOM to not be detected")
	}
}
