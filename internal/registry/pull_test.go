package registry_test

import (
	"os"
	"testing"

	"github.com/yourorg/scanner-worker/internal/registry"
)

func TestPullToTar(t *testing.T) {
	dest := t.TempDir() + "/image.tar"
	err := registry.PullToTar("alpine:3.20", dest, nil)
	if err != nil {
		t.Fatalf("PullToTar: %v", err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() < 1_000_000 {
		t.Fatalf("tar too small: %d bytes", info.Size())
	}
}
