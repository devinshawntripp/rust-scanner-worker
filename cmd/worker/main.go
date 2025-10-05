package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

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
    if err != nil { log.Fatal(err) }
    if err := store.Ping(ctx); err != nil { log.Fatal(err) }

	s3, err := s3c.New(cfg.S3Endpoint, cfg.S3AccessKey, cfg.S3SecretKey, cfg.S3UseSSL)
	if err != nil { log.Fatal(err) }

	// healthz
	if addr := cfg.HTTPAddr; addr != "" {
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
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
	if err := r.RunForever(ctx); err != nil {
		log.Fatal(err)
	}
}
