package dispatcher

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/yourorg/scanner-worker/internal/db"
	"github.com/yourorg/scanner-worker/internal/s3"
)

// DispatcherConfig holds config specific to the dispatcher.
type DispatcherConfig struct {
	Namespace              string
	Image                  string
	ServiceAccount         string
	EnvFromSecret          string
	EnvFromConfig          string
	PollInterval           time.Duration
	StaleJobTimeoutSeconds int
	StaleSweepSeconds      int
}

// Dispatcher polls for queued scan jobs and creates K8s Jobs for them.
type Dispatcher struct {
	cfg DispatcherConfig
	db  *db.Store
	s3  *s3.Client
	k8s kubernetes.Interface
}

// New creates a new Dispatcher.
func New(cfg DispatcherConfig, store *db.Store, s3c *s3.Client, k8s kubernetes.Interface) *Dispatcher {
	return &Dispatcher{cfg: cfg, db: store, s3: s3c, k8s: k8s}
}

// canSchedule checks whether the tier is under its concurrency limit.
func canSchedule(tier ResourceTier, activeCounts map[string]int) bool {
	return activeCounts[tier.Name] < tier.MaxConcurrent
}

// countActiveJobs queries K8s for active scan Jobs by tier.
func (d *Dispatcher) countActiveJobs(ctx context.Context) (map[string]int, error) {
	jobs, err := d.k8s.BatchV1().Jobs(d.cfg.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app=scanrook-scan",
	})
	if err != nil {
		return nil, fmt.Errorf("list scan jobs: %w", err)
	}
	counts := map[string]int{"small": 0, "medium": 0, "large": 0}
	for _, j := range jobs.Items {
		if isJobActive(&j) {
			tier := j.Labels["scanrook.io/tier"]
			counts[tier]++
		}
	}
	return counts, nil
}

// isJobActive returns true if the Job has not yet completed or failed.
func isJobActive(j *batchv1.Job) bool {
	for _, c := range j.Status.Conditions {
		if (c.Type == batchv1.JobComplete || c.Type == batchv1.JobFailed) && c.Status == "True" {
			return false
		}
	}
	return true
}

// Run starts the dispatcher poll loop.
func (d *Dispatcher) Run(ctx context.Context, workerID string) error {
	pollInterval := d.cfg.PollInterval
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	sweepInterval := time.Duration(d.cfg.StaleSweepSeconds) * time.Second
	nextSweep := time.Now()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if sweepInterval > 0 && time.Now().After(nextSweep) {
			d.reapStaleJobs(ctx)
			nextSweep = time.Now().Add(sweepInterval)
		}

		activeCounts, err := d.countActiveJobs(ctx)
		if err != nil {
			log.Printf("dispatcher: failed to count active jobs: %v", err)
			time.Sleep(pollInterval)
			continue
		}

		job, err := d.db.AcquireNextQueued(ctx, workerID)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}

		objSize, err := d.s3.GetObjectSize(ctx, job.Bucket, job.ObjectKey)
		if err != nil {
			log.Printf("dispatcher: job %s: failed to get object size: %v", job.ID, err)
			_ = d.db.MarkFailed(ctx, job.ID, "failed to get artifact size: "+err.Error())
			continue
		}

		tier := ClassifyTier(objSize)

		if !canSchedule(tier, activeCounts) {
			log.Printf("dispatcher: job %s: tier %s at capacity (%d/%d), re-queuing",
				job.ID, tier.Name, activeCounts[tier.Name], tier.MaxConcurrent)
			_ = d.db.RequeueJob(ctx, job.ID)
			time.Sleep(pollInterval)
			continue
		}

		rayonThreads := 1
		switch tier.Name {
		case "medium":
			rayonThreads = 2
		case "large":
			rayonThreads = 3
		}

		// Inherit proxy env vars so scan pods can reach external APIs
		proxyEnvs := map[string]string{}
		for _, key := range []string{
			"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
			"http_proxy", "https_proxy", "no_proxy",
			"S3_ENDPOINT", "SCANNER_FORCE_IPV4",
			"SCANNER_OSV_TIMEOUT_SECS", "SCANNER_OSV_RETRIES", "SCANNER_OSV_BACKOFF_MS",
			"SCANNER_NVD_ENRICH", "SCANNER_NVD_CONC", "SCANNER_NVD_SLEEP_MS", "SCANNER_NVD_SKIP_FULLY_ENRICHED",
			"SCANNER_REDHAT_ENRICH", "SCANNER_REDHAT_TIMEOUT_SECS", "SCANNER_REDHAT_SLEEP_MS", "SCANNER_REDHAT_TTL_DAYS",
		} {
			if v := os.Getenv(key); v != "" {
				proxyEnvs[key] = v
			}
		}

		scanJob := BuildScanJob(ScanJobOpts{
			JobID:          job.ID,
			Namespace:      d.cfg.Namespace,
			Image:          d.cfg.Image,
			Tier:           tier,
			EnvVars:        proxyEnvs,
			EnvFromSecret:  d.cfg.EnvFromSecret,
			EnvFromConfig:  d.cfg.EnvFromConfig,
			RayonThreads:   rayonThreads,
			ServiceAccount: d.cfg.ServiceAccount,
		})

		_, err = d.k8s.BatchV1().Jobs(d.cfg.Namespace).Create(ctx, scanJob, metav1.CreateOptions{})
		if err != nil {
			log.Printf("dispatcher: job %s: failed to create K8s Job: %v", job.ID, err)
			_ = d.db.MarkFailed(ctx, job.ID, "failed to create scan job: "+err.Error())
			continue
		}

		log.Printf("dispatcher: job %s: created K8s Job scan-%s (tier=%s cpu=%s mem=%s)",
			job.ID, job.ID, tier.Name, tier.CPURequest, tier.MemoryRequest)
	}
}

func (d *Dispatcher) reapStaleJobs(ctx context.Context) {
	idleFor := time.Duration(d.cfg.StaleJobTimeoutSeconds) * time.Second
	if idleFor <= 0 {
		return
	}
	ids, err := d.db.FailStaleRunning(ctx, idleFor)
	if err != nil {
		log.Printf("dispatcher: stale sweep failed: %v", err)
		return
	}
	for _, id := range ids {
		msg := fmt.Sprintf("no progress for %s", idleFor.Round(time.Second))
		_ = d.db.InsertEvent(ctx, id, time.Now(), "dispatcher.stale.fail", msg, nil)
		log.Printf("dispatcher: job %s: marked failed by stale sweep", id)
		_ = d.k8s.BatchV1().Jobs(d.cfg.Namespace).Delete(ctx,
			fmt.Sprintf("scan-%s", id), metav1.DeleteOptions{})
	}
}
