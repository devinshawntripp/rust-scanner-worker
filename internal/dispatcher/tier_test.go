package dispatcher

import "testing"

func TestClassifyTier_Small(t *testing.T) {
	tier := ClassifyTier(100 * 1024 * 1024) // 100 MB
	if tier.Name != "small" {
		t.Fatalf("expected small, got %s", tier.Name)
	}
	if tier.CPURequest != "1" || tier.MemoryRequest != "1Gi" {
		t.Fatalf("unexpected resources: cpu=%s mem=%s", tier.CPURequest, tier.MemoryRequest)
	}
}

func TestClassifyTier_Medium(t *testing.T) {
	tier := ClassifyTier(2 * 1024 * 1024 * 1024) // 2 GB
	if tier.Name != "medium" {
		t.Fatalf("expected medium, got %s", tier.Name)
	}
	if tier.CPURequest != "2" || tier.MemoryRequest != "2Gi" {
		t.Fatalf("unexpected resources: cpu=%s mem=%s", tier.CPURequest, tier.MemoryRequest)
	}
}

func TestClassifyTier_Large(t *testing.T) {
	tier := ClassifyTier(10 * 1024 * 1024 * 1024) // 10 GB
	if tier.Name != "large" {
		t.Fatalf("expected large, got %s", tier.Name)
	}
	if tier.CPURequest != "3" || tier.MemoryRequest != "4Gi" {
		t.Fatalf("unexpected resources: cpu=%s mem=%s", tier.CPURequest, tier.MemoryRequest)
	}
}

func TestClassifyTier_Zero(t *testing.T) {
	tier := ClassifyTier(0)
	if tier.Name != "small" {
		t.Fatalf("zero size should be small, got %s", tier.Name)
	}
}

func TestClassifyTier_ExactSmallThreshold(t *testing.T) {
	tier := ClassifyTier(500 * 1024 * 1024) // exactly 500 MB
	if tier.Name != "medium" {
		t.Fatalf("exact threshold should be medium, got %s", tier.Name)
	}
}

func TestClassifyTier_ExactLargeThreshold(t *testing.T) {
	tier := ClassifyTier(5 * 1024 * 1024 * 1024) // exactly 5 GB
	if tier.Name != "large" {
		t.Fatalf("exact threshold should be large, got %s", tier.Name)
	}
}
