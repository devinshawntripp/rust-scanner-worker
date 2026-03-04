package db

import (
	"testing"
)

// TestOpenPoolSizing verifies that the pool configuration formula produces the
// correct MaxConns value for various concurrency settings. This test runs
// without a live database by calling poolConfig() directly.
func TestOpenPoolSizing(t *testing.T) {
	// Use a syntactically valid but non-connectable URL — poolConfig only parses it.
	url := "postgres://test:test@localhost:5432/test"

	cases := []struct {
		concurrency int
		wantMax     int32
	}{
		{1, 5},  // 1 + 4
		{2, 6},  // 2 + 4
		{4, 8},  // 4 + 4
	}

	for _, tc := range cases {
		cfg, err := poolConfig(url, tc.concurrency)
		if err != nil {
			t.Fatalf("poolConfig(%d): unexpected error: %v", tc.concurrency, err)
		}
		if cfg.MaxConns != tc.wantMax {
			t.Errorf("poolConfig(%d): MaxConns = %d, want %d", tc.concurrency, cfg.MaxConns, tc.wantMax)
		}
		if cfg.MinConns != 1 {
			t.Errorf("poolConfig(%d): MinConns = %d, want 1", tc.concurrency, cfg.MinConns)
		}
	}
}
