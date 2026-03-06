package registry

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// PullToTar pulls an image from a registry and writes it as a tar file.
// The tar format is compatible with `docker load` and the scanrook scanner.
func PullToTar(ref string, destPath string, creds *Credentials) error {
	r, err := name.ParseReference(ref)
	if err != nil {
		return fmt.Errorf("parse ref: %w", err)
	}
	img, err := ResolveImage(ref, creds)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}
	tag, ok := r.(name.Tag)
	if !ok {
		tag = r.Context().Tag("latest")
	}
	if err := tarball.WriteToFile(destPath, tag, img); err != nil {
		return fmt.Errorf("write tar: %w", err)
	}
	return nil
}
