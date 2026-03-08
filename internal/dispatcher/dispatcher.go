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

	registryCrypto "github.com/yourorg/scanner-worker/internal/crypto"
	"github.com/yourorg/scanner-worker/internal/db"
	"github.com/yourorg/scanner-worker/internal/s3"
)

// DispatcherConfig holds config specific to the dispatcher.
type DispatcherConfig struct {
	Namespace              string
	Image                  string
	RegistryPullerImage    string // image for registry-puller init container
	RegistryEncryptionKey  string // hex-encoded AES-256-GCM key for decrypting registry tokens
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
			d.reconcileFailedK8sJobs(ctx)
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

		// Determine tier — registry jobs skip S3 size check (object doesn't exist yet)
		var tier ResourceTier
		isRegistry := job.SourceType == "registry"

		if isRegistry {
			// Registry jobs use medium tier by default since image size is unknown
			tier = TierMedium
		} else {
			objSize, err := d.s3.GetObjectSize(ctx, job.Bucket, job.ObjectKey)
			if err != nil {
				log.Printf("dispatcher: job %s: failed to get object size: %v", job.ID, err)
				_ = d.db.MarkFailed(ctx, job.ID, "failed to get artifact size: "+err.Error())
				continue
			}
			tier = ClassifyTier(objSize)
		}

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
			"SCANNER_OSV_TIMEOUT_SECS", "SCANNER_OSV_RETRIES", "SCANNER_OSV_BACKOFF_MS", "SCANNER_OSV_FETCH_CVE_DETAILS",
			"SCANNER_NVD_ENRICH", "SCANNER_NVD_CONC", "SCANNER_NVD_SLEEP_MS", "SCANNER_NVD_SKIP_FULLY_ENRICHED",
			"SCANNER_REDHAT_ENRICH", "SCANNER_REDHAT_TIMEOUT_SECS", "SCANNER_REDHAT_SLEEP_MS", "SCANNER_REDHAT_TTL_DAYS",
		} {
			if v := os.Getenv(key); v != "" {
				proxyEnvs[key] = v
			}
		}

		// Resolve registry credentials for init container
		var regOpts *RegistryInitOpts
		if isRegistry && job.RegistryImage != nil {
			regOpts = &RegistryInitOpts{
				PullerImage:   d.cfg.RegistryPullerImage,
				RegistryImage: *job.RegistryImage,
			}
			// Look up credentials only for private registries (registry_config_id set)
			if job.RegistryConfigID != nil && job.OrgID != nil {
				creds, err := d.db.GetRegistryCredentials(ctx, *job.RegistryConfigID, *job.OrgID)
				if err != nil {
					log.Printf("dispatcher: job %s: failed to get registry creds: %v", job.ID, err)
					_ = d.db.MarkFailed(ctx, job.ID, "failed to resolve registry credentials: "+err.Error())
					continue
				}
				if creds.Username != nil {
					regOpts.Username = *creds.Username
				}
				if len(creds.TokenEncrypted) > 0 && d.cfg.RegistryEncryptionKey != "" {
					token, err := registryCrypto.DecryptAES256GCM(d.cfg.RegistryEncryptionKey, creds.TokenEncrypted)
					if err != nil {
						log.Printf("dispatcher: job %s: failed to decrypt registry token: %v", job.ID, err)
						_ = d.db.MarkFailed(ctx, job.ID, "failed to decrypt registry token: "+err.Error())
						continue
					}
					regOpts.Token = token
				}
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
			Registry:       regOpts,
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

// reconcileFailedK8sJobs checks for K8s Jobs that have failed (including
// init container failures like registry-puller) and marks the corresponding
// scan_jobs rows as failed so they don't stay stuck in 'running'.
func (d *Dispatcher) reconcileFailedK8sJobs(ctx context.Context) {
	jobs, err := d.k8s.BatchV1().Jobs(d.cfg.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app=scanrook-scan",
	})
	if err != nil {
		log.Printf("dispatcher: reconcile: failed to list K8s jobs: %v", err)
		return
	}
	for _, j := range jobs.Items {
		for _, c := range j.Status.Conditions {
			if c.Type == batchv1.JobFailed && c.Status == "True" {
				jobID := j.Labels["scanrook.io/job-id"]
				if jobID == "" {
					continue
				}
				reason := c.Reason
				if reason == "" {
					reason = "K8s Job failed"
				}
				msg := fmt.Sprintf("K8s Job %s failed: %s — %s", j.Name, reason, c.Message)
				log.Printf("dispatcher: job %s: %s", jobID, msg)
				_ = d.db.MarkFailed(ctx, jobID, msg)
				_ = d.db.InsertEvent(ctx, jobID, time.Now(), "dispatcher.k8s.failed", msg, nil)
				// Clean up the failed K8s Job
				_ = d.k8s.BatchV1().Jobs(d.cfg.Namespace).Delete(ctx,
					j.Name, metav1.DeleteOptions{})
				break
			}
		}
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
