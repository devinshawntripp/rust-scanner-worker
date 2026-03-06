package registry

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Credentials for authenticating to a registry.
type Credentials struct {
	Username string
	Password string // or token
}

// authenticator returns an authn.Authenticator from credentials, or anonymous.
func authenticator(creds *Credentials) authn.Authenticator {
	if creds == nil || (creds.Username == "" && creds.Password == "") {
		return authn.Anonymous
	}
	return &authn.Basic{Username: creds.Username, Password: creds.Password}
}

// ResolveImage resolves an image reference to a v1.Image.
// Handles manifest lists by selecting linux/amd64.
func ResolveImage(ref string, creds *Credentials) (v1.Image, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse ref %q: %w", ref, err)
	}
	opts := []remote.Option{remote.WithAuth(authenticator(creds))}
	desc, err := remote.Get(r, opts...)
	if err != nil {
		return nil, fmt.Errorf("fetch %q: %w", ref, err)
	}
	return desc.Image()
}

// ListTags returns all tags for a repository on a given registry.
func ListTags(registryURL, repository string, creds *Credentials) ([]string, error) {
	repo, err := name.NewRepository(registryURL + "/" + repository)
	if err != nil {
		return nil, fmt.Errorf("parse repo: %w", err)
	}
	opts := []remote.Option{remote.WithAuth(authenticator(creds))}
	return remote.List(repo, opts...)
}

// ImageSize returns the total compressed layer size in bytes.
func ImageSize(ref string, creds *Credentials) (int64, error) {
	img, err := ResolveImage(ref, creds)
	if err != nil {
		return 0, err
	}
	manifest, err := img.Manifest()
	if err != nil {
		return 0, fmt.Errorf("manifest: %w", err)
	}
	var total int64
	for _, l := range manifest.Layers {
		total += l.Size
	}
	return total, nil
}
