package db

import (
	"context"
	"fmt"
)

// RegistryCredentials holds the raw data needed to pull from a registry.
type RegistryCredentials struct {
	RegistryURL    string
	Username       *string
	TokenEncrypted []byte // raw AES-256-GCM blob; caller must decrypt
}

// GetRegistryCredentials fetches the credentials for a registry config by ID and org.
func (s *Store) GetRegistryCredentials(ctx context.Context, registryConfigID string, orgID string) (*RegistryCredentials, error) {
	row := s.Pool.QueryRow(ctx, `
		SELECT registry_url, username, token_encrypted
		FROM registry_configs
		WHERE id = $1::uuid AND org_id = $2::uuid
	`, registryConfigID, orgID)

	var creds RegistryCredentials
	if err := row.Scan(&creds.RegistryURL, &creds.Username, &creds.TokenEncrypted); err != nil {
		return nil, fmt.Errorf("registry config not found: %w", err)
	}
	return &creds, nil
}
