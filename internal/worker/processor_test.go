package worker

import (
	"testing"
)

func TestProcessorConfig_Validate(t *testing.T) {
	cfg := ProcessorConfig{
		ScratchDir:                 "/scratch",
		ScannerPath:                "/usr/local/bin/scanrook",
		ScannerTimeoutSeconds:      1800,
		MaxArtifactBytes:           21474836480,
		ReportsBucket:              "reports",
		WorkerIngestTimeoutSeconds: 300,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid config should not error: %v", err)
	}
}

func TestProcessorConfig_Validate_MissingScannerPath(t *testing.T) {
	cfg := ProcessorConfig{}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty ScannerPath")
	}
}

func TestProcessorConfig_Validate_MissingReportsBucket(t *testing.T) {
	cfg := ProcessorConfig{ScannerPath: "/usr/local/bin/scanrook"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty ReportsBucket")
	}
}

func TestProcessorConfig_Validate_MissingScratchDir(t *testing.T) {
	cfg := ProcessorConfig{ScannerPath: "/usr/local/bin/scanrook", ReportsBucket: "reports"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty ScratchDir")
	}
}
