package worker

import (
	"log"
	"time"

	"github.com/sony/gobreaker"
)

const (
	// scannerBreakerConsecutiveFailures is the number of consecutive non-timeout
	// scanner failures required to trip the circuit breaker open.
	scannerBreakerConsecutiveFailures = 5

	// scannerBreakerTimeout is how long the circuit stays open before allowing
	// a single probe request (transitioning to half-open state).
	scannerBreakerTimeout = 60 * time.Second
)

// newScannerBreaker creates a circuit breaker configured for scanner binary
// execution. It trips after scannerBreakerConsecutiveFailures consecutive
// non-timeout failures and resets after scannerBreakerTimeout in open state.
func newScannerBreaker() *gobreaker.CircuitBreaker {
	st := gobreaker.Settings{
		Name: "scanner",
		// MaxRequests is the maximum number of requests allowed to pass through
		// when the circuit breaker is half-open. 1 means one probe at a time.
		MaxRequests: 1,
		// Timeout is the period of the open state before the circuit breaker
		// sets itself to half-open to allow a probe.
		Timeout: scannerBreakerTimeout,
		// ReadyToTrip is called when a request fails in the closed state.
		// It returns true if the circuit breaker should trip to open.
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= scannerBreakerConsecutiveFailures
		},
		// OnStateChange is called whenever the circuit breaker state changes.
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			log.Printf("[circuit-breaker] %s: %s -> %s", name, from, to)
		},
	}
	return gobreaker.NewCircuitBreaker(st)
}
