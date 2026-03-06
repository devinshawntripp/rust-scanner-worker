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
	if err := store.Ping(ctx); err != nil {
		log.Fatalf("db ping: %v", err)
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
		ServiceAccount:         os.Getenv("DISPATCHER_SERVICE_ACCOUNT"),
		EnvFromSecret:          os.Getenv("DISPATCHER_ENV_SECRET"),
		EnvFromConfig:          os.Getenv("DISPATCHER_ENV_CONFIGMAP"),
		PollInterval:           2 * time.Second,
		StaleJobTimeoutSeconds: staleTimeout,
		StaleSweepSeconds:      staleSweep,
	}

	// ---- health endpoint ----
	if httpAddr != "" {
		go func() {
			mux := http.NewServeMux()
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
			srv := &http.Server{Addr: httpAddr, Handler: mux}
			go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()
			log.Printf("health endpoint listening on %s", httpAddr)
			if err := srv.ListenAndServe(); err != http.ErrServerClosed {
				log.Printf("health server error: %v", err)
			}
		}()
	}

	// ---- run ----
	workerID := uuid.New().String()
	log.Printf("dispatcher starting: id=%s namespace=%s image=%s", workerID, namespace, image)

	d := dispatcher.New(dcfg, store, s3, k8sClient)
	if err := d.Run(ctx, workerID); err != nil {
		log.Fatal(err)
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
