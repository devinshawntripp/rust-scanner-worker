package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/yourorg/scanner-worker/internal/db"
	"github.com/yourorg/scanner-worker/internal/dispatcher"
	s3c "github.com/yourorg/scanner-worker/internal/s3"
)

func main() {
	_ = godotenv.Load(".env.local")
	_ = godotenv.Load(".env")

	// ---- required env ----
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	s3Endpoint := os.Getenv("S3_ENDPOINT")
	s3AccessKey := os.Getenv("S3_ACCESS_KEY")
	s3SecretKey := os.Getenv("S3_SECRET_KEY")
	s3UseSSL, _ := strconv.ParseBool(os.Getenv("S3_USE_SSL"))

	image := os.Getenv("DISPATCHER_SCAN_IMAGE")
	if image == "" {
		log.Fatal("DISPATCHER_SCAN_IMAGE is required")
	}

	// ---- optional env ----
	namespace := os.Getenv("DISPATCHER_NAMESPACE")
	if namespace == "" {
		namespace = "scanrook"
	}
	httpAddr := os.Getenv("HTTP_ADDR")
	staleTimeout := getIntEnv("WORKER_STALE_JOB_TIMEOUT_SECONDS", 1800)
	staleSweep := getIntEnv("WORKER_STALE_SWEEP_SECONDS", 60)

	// ---- context ----
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// ---- PostgreSQL ----
	store, err := db.Open(ctx, databaseURL, 1)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	// Retry the startup ping with bounded backoff. During a CNPG primary
	// failover the pg-shared-rw ClusterIP briefly has no backend, and Cilium's
	// connect-time socket LB returns EPERM until the new primary is promoted.
	// A single ping + Fatalf turns that transient window into a crash-loop, so
	// absorb it here instead of relying on kubelet restarts.
	if err := pingWithRetry(ctx, store, 60*time.Second); err != nil {
		log.Fatalf("db ping (after retries): %v", err)
	}

	// ---- S3 / MinIO ----
	s3, err := s3c.New(s3Endpoint, s3AccessKey, s3SecretKey, s3UseSSL)
	if err != nil {
		log.Fatalf("s3 client: %v", err)
	}

	// ---- Kubernetes ----
	k8sCfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("in-cluster k8s config: %v", err)
	}
	k8sClient, err := kubernetes.NewForConfig(k8sCfg)
	if err != nil {
		log.Fatalf("k8s client: %v", err)
	}

	// ---- dispatcher config ----
	dcfg := dispatcher.DispatcherConfig{
		Namespace:              namespace,
		Image:                  image,
		RegistryPullerImage:    os.Getenv("REGISTRY_PULLER_IMAGE"),
		RegistryEncryptionKey:  os.Getenv("REGISTRY_ENCRYPTION_KEY"),
		ServiceAccount:         os.Getenv("DISPATCHER_SERVICE_ACCOUNT"),
		EnvFromSecret:          os.Getenv("DISPATCHER_ENV_SECRET"),
		EnvFromConfig:          os.Getenv("DISPATCHER_ENV_CONFIGMAP"),
		PollInterval:           2 * time.Second,
		StaleJobTimeoutSeconds: staleTimeout,
		StaleSweepSeconds:      staleSweep,
	}

	d := dispatcher.New(dcfg, store, s3, k8sClient)

	// ---- HTTP server (health + job management) ----
	if httpAddr != "" {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
				dbCtx, c := context.WithTimeout(r.Context(), 2*time.Second)
				defer c()
				if err := store.Ping(dbCtx); err != nil {
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte(`{"status":"unhealthy"}`))
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"healthy"}`))
			})
			d.RegisterHandlers(mux)
			srv := &http.Server{Addr: httpAddr, Handler: mux}
			go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()
			log.Printf("HTTP server listening on %s (health + job management)", httpAddr)
			if err := srv.ListenAndServe(); err != http.ErrServerClosed {
				log.Printf("HTTP server error: %v", err)
			}
		}()
	}

	// ---- run ----
	workerID := uuid.New().String()
	log.Printf("dispatcher starting: id=%s namespace=%s image=%s", workerID, namespace, image)

	if err := d.Run(ctx, workerID); err != nil {
		log.Fatal(err)
	}
}

// pingWithRetry pings the DB, retrying with exponential backoff (capped at 5s
// per attempt) until it succeeds or maxWait elapses. Tolerates the transient
// connect failures seen during a Postgres primary failover.
func pingWithRetry(ctx context.Context, store *db.Store, maxWait time.Duration) error {
	deadline := time.Now().Add(maxWait)
	backoff := 500 * time.Millisecond
	var lastErr error
	for {
		if err := store.Ping(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().Add(backoff).After(deadline) {
			return lastErr
		}
		log.Printf("db ping failed (%v); retrying in %s", lastErr, backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}

func getIntEnv(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
