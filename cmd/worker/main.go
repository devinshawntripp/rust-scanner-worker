package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/joho/godotenv"
	"github.com/yourorg/scanner-worker/internal/config"
	"github.com/yourorg/scanner-worker/internal/db"
	s3c "github.com/yourorg/scanner-worker/internal/s3"
	"github.com/yourorg/scanner-worker/internal/worker"
)

func main() {
	// Load environment variables from .env files if present. This helps local dev.
	// Try current directory and one level up (in case run from cmd/worker).
	_ = godotenv.Load(".env.local")
	_ = godotenv.Load(".env")
	_ = godotenv.Load("../.env")

	cfg := config.Load()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	store, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	if err := store.Ping(ctx); err != nil {
		log.Fatal(err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		if isInsufficientPrivilege(err) {
			log.Printf("ensure schema skipped due insufficient privilege: %v", err)
		} else {
			log.Fatal(err)
		}
	}

	s3, err := s3c.New(cfg.S3Endpoint, cfg.S3AccessKey, cfg.S3SecretKey, cfg.S3UseSSL)
	if err != nil {
		log.Fatal(err)
	}

	// Print scanner version/help at startup for verification
	cmd := exec.CommandContext(ctx, cfg.ScannerPath, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("scanner --help failed: %v", err)
	}
	if len(out) > 0 {
		log.Printf("scanner help:\n%s", string(out))
	}

	// healthz — checks DB connectivity with a 2s timeout; returns 503 if unreachable
	if addr := cfg.HTTPAddr; addr != "" {
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
				dbCtx, dbCancel := context.WithTimeout(r.Context(), 2*time.Second)
				defer dbCancel()
				if err := store.Ping(dbCtx); err != nil {
					log.Printf("healthz: db ping failed: %v", err)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte(`{"status":"unhealthy","reason":"db unreachable"}`))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"healthy"}`))
			})
			s := &http.Server{Addr: addr, Handler: mux}
			go func() {
				<-ctx.Done()
				shctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = s.Shutdown(shctx)
			}()
			if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("health server: %v", err)
			}
		}()
	}

	r := worker.NewRunner(cfg, store, s3)
	log.Printf("worker starting with id=%s concurrency=%d", r.WorkerID(), cfg.WorkerConcurrency)

	// Graceful job recovery: re-queue any jobs stuck in 'running' with no
	// recent heartbeat events (orphaned by crashed workers).
	r.RecoverStaleJobs(ctx)

	if err := r.RunForever(ctx); err != nil {
		log.Fatal(err)
	}
}

func isInsufficientPrivilege(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42501"
}
