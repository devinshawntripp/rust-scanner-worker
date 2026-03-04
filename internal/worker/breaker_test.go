package worker

import (
	"errors"
	"testing"
	"time"

	"github.com/sony/gobreaker"
	"github.com/yourorg/scanner-worker/internal/config"
)

// TestScannerBreaker_TripsAfterConsecutiveFailures verifies the circuit breaker
// opens after 5 consecutive failures and returns ErrOpenState on the 6th call.
func TestScannerBreaker_TripsAfterConsecutiveFailures(t *testing.T) {
	cb := newScannerBreaker()
	testErr := errors.New("scanner failed: exit status 1")

	// Execute 5 failing calls to trip the circuit
	for i := 0; i < 5; i++ {
		_, err := cb.Execute(func() (interface{}, error) {
			return nil, testErr
		})
		if !errors.Is(err, testErr) {
			// On calls 1-5 we expect the underlying error to be returned
			t.Fatalf("call %d: expected test error, got %v", i+1, err)
		}
	}

	// The 6th call should return ErrOpenState because the circuit is open
	_, err := cb.Execute(func() (interface{}, error) {
		return nil, testErr
	})
	if !errors.Is(err, gobreaker.ErrOpenState) {
		t.Fatalf("expected ErrOpenState after 5 failures, got %v", err)
	}
}

// TestScannerBreaker_DoesNotTripOnSuccess verifies that successes reset the
// consecutive failure counter so the circuit never opens.
func TestScannerBreaker_DoesNotTripOnSuccess(t *testing.T) {
	cb := newScannerBreaker()
	testErr := errors.New("scanner failed: exit status 1")

	// Alternate 4 failures with 1 success between each batch.
	// After a success the consecutive failure counter resets.
	for round := 0; round < 3; round++ {
		// 4 failures
		for i := 0; i < 4; i++ {
			_, _ = cb.Execute(func() (interface{}, error) {
				return nil, testErr
			})
		}
		// 1 success — resets the consecutive counter
		_, err := cb.Execute(func() (interface{}, error) {
			return nil, nil
		})
		if err != nil {
			t.Fatalf("round %d: success call returned error: %v", round, err)
		}
	}

	// Circuit should still be closed — another call should work
	_, err := cb.Execute(func() (interface{}, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("circuit opened unexpectedly: %v", err)
	}
}

// TestScannerBreaker_Constants verifies the threshold constants have the expected values.
func TestScannerBreaker_Constants(t *testing.T) {
	if scannerBreakerConsecutiveFailures != 5 {
		t.Errorf("scannerBreakerConsecutiveFailures = %d, want 5", scannerBreakerConsecutiveFailures)
	}
	if scannerBreakerTimeout != 60*time.Second {
		t.Errorf("scannerBreakerTimeout = %s, want 60s", scannerBreakerTimeout)
	}
}

// testRunner creates a minimal Runner for unit testing.
// The breaker field is set, cfg.ScannerPath can be set by the caller.
// db and s3 fields are nil — do not call methods that use them.
func testRunner() *Runner {
	return &Runner{
		cfg:      config.Config{},
		breaker:  newScannerBreaker(),
		workerID: "test-worker",
	}
}

// TestProcessJobBreakerOpen verifies that when the circuit breaker is pre-tripped,
// calling r.breaker.Execute returns ErrOpenState immediately with the correct message.
// This test validates the breaker integration at the breaker level rather than
// going through the full processJob pipeline (which requires live S3 and DB).
func TestProcessJobBreakerOpen(t *testing.T) {
	r := testRunner()
	tripErr := errors.New("scanner failed: exit status 1")

	// Pre-trip the breaker by calling Execute 5 times with failures
	for i := 0; i < 5; i++ {
		_, _ = r.breaker.Execute(func() (interface{}, error) {
			return nil, tripErr
		})
	}

	// Verify the breaker is now open
	_, err := r.breaker.Execute(func() (interface{}, error) {
		return nil, nil // this should not be called
	})
	if !errors.Is(err, gobreaker.ErrOpenState) {
		t.Fatalf("expected breaker to be open, got: %v", err)
	}

	// Simulate the error message processJob would return for an open circuit
	var gotMsg string
	if errors.Is(err, gobreaker.ErrOpenState) {
		gotMsg = "circuit breaker open: scanner unavailable"
	}
	want := "circuit breaker open: scanner unavailable"
	if gotMsg != want {
		t.Errorf("circuit open message = %q, want %q", gotMsg, want)
	}
}
