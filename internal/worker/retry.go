package worker

import (
	"context"
	"math/rand"
	"time"
)

// retry executes fn up to maxAttempts times with jittered exponential backoff.
// Base delay doubles on each attempt: 200ms -> 400ms -> 800ms, etc.
// Random jitter of 0-50% of the current delay is added to avoid thundering herd.
func retry(ctx context.Context, maxAttempts int, baseDelay time.Duration, fn func() error) error {
	var lastErr error
	delay := baseDelay
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if attempt == maxAttempts {
			break
		}
		if ctx.Err() != nil {
			return lastErr
		}
		// Jittered exponential backoff: delay + random(0, delay/2)
		jitter := time.Duration(rand.Int63n(int64(delay / 2)))
		select {
		case <-ctx.Done():
			return lastErr
		case <-time.After(delay + jitter):
		}
		delay *= 2
	}
	return lastErr
}
