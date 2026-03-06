package registry_test

import (
	"testing"

	"github.com/yourorg/scanner-worker/internal/registry"
)

func TestResolvePublicImage(t *testing.T) {
	img, err := registry.ResolveImage("alpine:3.20", nil)
	if err != nil {
		t.Fatalf("ResolveImage: %v", err)
	}
	manifest, err := img.Manifest()
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if len(manifest.Layers) == 0 {
		t.Fatal("expected at least one layer")
	}
}

func TestListTags(t *testing.T) {
	tags, err := registry.ListTags("registry-1.docker.io", "library/alpine", nil)
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if len(tags) < 10 {
		t.Fatalf("expected many tags, got %d", len(tags))
	}
	found := false
	for _, tag := range tags {
		if tag == "latest" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected 'latest' tag")
	}
}

func TestImageSize(t *testing.T) {
	size, err := registry.ImageSize("alpine:3.20", nil)
	if err != nil {
		t.Fatalf("ImageSize: %v", err)
	}
	// Alpine compressed is ~3-4MB
	if size < 1_000_000 || size > 20_000_000 {
		t.Fatalf("unexpected size: %d", size)
	}
}
