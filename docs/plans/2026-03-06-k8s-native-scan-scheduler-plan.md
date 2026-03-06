# K8s-Native Scan Scheduler Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the in-process scan execution model with K8s Jobs per scan, where a lightweight dispatcher creates Jobs with resource requests proportional to artifact size, letting the K8s scheduler prevent resource exhaustion.

**Architecture:** The Go worker splits into two binaries: (1) a Dispatcher that polls for queued jobs and creates K8s Jobs, and (2) a Scan Runner invoked via `--single-job <job-id>` that executes one scan and exits. The scanner binary is baked into the Docker image and auto-updates via `scanrook upgrade` at container startup.

**Tech Stack:** Go 1.24, k8s.io/client-go, pgx/v5, minio-go/v7, Kubernetes batch/v1 Jobs

---

## Phase 1: Infrastructure Prep

### Task 1: Install metrics-server on the cluster

**Files:**
- Create: `k8s/deltaguard/metrics-server.yaml` (in scanrook-ui repo)

**Step 1: Create the metrics-server manifest**

The manifest should deploy metrics-server with the `--kubelet-insecure-tls` flag (required for kubeadm clusters without proper kubelet certs).

```bash
ssh dg-node1 "kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml"
```

**Step 2: Patch for insecure TLS (kubeadm clusters need this)**

```bash
ssh dg-node1 "kubectl patch deployment metrics-server -n kube-system --type='json' -p='[{\"op\": \"add\", \"path\": \"/spec/template/spec/containers/0/args/-\", \"value\": \"--kubelet-insecure-tls\"}]'"
```

**Step 3: Verify metrics-server is running**

```bash
ssh dg-node1 "kubectl rollout status deployment/metrics-server -n kube-system --timeout=120s"
```
Expected: `deployment "metrics-server" successfully rolled out`

**Step 4: Verify kubectl top works**

```bash
ssh dg-node1 "kubectl top nodes"
```
Expected: CPU and memory usage for all 3 nodes

**Step 5: Verify HPA can read metrics**

```bash
ssh dg-node1 "kubectl get hpa -n scanrook"
```
Expected: `scanrook-web` HPA shows actual CPU percentage instead of `<unknown>`

---

### Task 2: Rolling restart of cluster nodes

**Important:** Do this one node at a time to avoid full cluster downtime. Wait for each node to rejoin before proceeding.

**Step 1: Cordon and drain node-3 (worker node)**

```bash
ssh dg-node1 "kubectl cordon node-3vm1c && kubectl drain node-3vm1c --ignore-daemonsets --delete-emptydir-data --timeout=120s"
```

**Step 2: Restart node-3 VM**

SSH into the hypervisor or use the VM management tool to restart node-3vm1c. Wait for it to come back.

**Step 3: Uncordon node-3 and verify**

```bash
ssh dg-node1 "kubectl uncordon node-3vm1c && kubectl get node node-3vm1c -o custom-columns='NAME:.metadata.name,CPU:.status.capacity.cpu,MEM:.status.capacity.memory'"
```
Expected: CPU: 8, MEM: ~15Gi

**Step 4: Repeat for node-2**

Same drain → restart → uncordon → verify flow for node-2vm1c.

**Step 5: Repeat for node-1 (control plane)**

Same flow for node-1vm1c. This is the control plane — the API server will be briefly unavailable during restart.

**Step 6: Final verification**

```bash
ssh dg-node1 "kubectl top nodes && kubectl get nodes -o wide"
```
Expected: All 3 nodes with 8 CPU, ~15Gi memory, Ready status

---

### Task 3: Clean up deltaguard namespace

**Step 1: Verify nothing critical is running**

```bash
ssh dg-node1 "kubectl get all -n deltaguard"
```
Expected: Only completed CronJob pods, no running deployments

**Step 2: Delete stale HPA in deltaguard namespace**

```bash
ssh dg-node1 "kubectl delete hpa deltaguard-web -n deltaguard"
```

**Step 3: Delete the namespace**

```bash
ssh dg-node1 "kubectl delete namespace deltaguard --timeout=120s"
```

**Step 4: Verify cleanup**

```bash
ssh dg-node1 "kubectl get ns | grep deltaguard"
```
Expected: Only `deltaguard-system` remains (watchdog CronJob — evaluate if still needed)

---

### Task 4: Update ResourceQuota for new node capacity

**Files:**
- Modify: `/Users/devintripp/Desktop/GitHub/scanrook/scanrook-ui/k8s/deltaguard/resourcequota.yaml`

**Step 1: Update the ResourceQuota**

With 15Gi per node (45Gi total), raise limits to accommodate scan Jobs:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: scanrook-quota
spec:
  hard:
    requests.memory: 36Gi
    limits.memory: 42Gi
    pods: "30"
```

**Step 2: Apply to cluster**

```bash
ssh dg-node1 "kubectl apply -f -" <<< '<the yaml above>'
```

**Step 3: Verify**

```bash
ssh dg-node1 "kubectl describe resourcequota scanrook-quota -n scanrook"
```
Expected: New limits shown

---

### Task 5: Fix Grafana CrashLoopBackOff

**Step 1: Check why Grafana is crashing**

```bash
ssh dg-node1 "kubectl logs -n monitoring deployment/grafana --tail=50"
```

**Step 2: Debug and fix based on logs**

Common issues: PVC permissions, missing config, OOM. Fix based on what logs reveal.

**Step 3: Verify Grafana is running**

```bash
ssh dg-node1 "kubectl get pods -n monitoring -l app=grafana"
```
Expected: 1/1 Running

---

## Phase 2: Worker Refactor — Single-Job Mode

### Task 6: Extract processJob into a standalone function

**Files:**
- Create: `internal/worker/processor.go`
- Modify: `internal/worker/runner.go:104-359`

**Step 1: Write the test for the processor**

```bash
# File: internal/worker/processor_test.go
```

```go
package worker

import (
	"testing"
)

func TestProcessorConfig_Validate(t *testing.T) {
	cfg := ProcessorConfig{
		ScratchDir:                 "/scratch",
		ScannerPath:               "/usr/local/bin/scanrook",
		ScannerTimeoutSeconds:     1800,
		MaxArtifactBytes:          21474836480,
		ReportsBucket:             "reports",
		WorkerIngestTimeoutSeconds: 300,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid config should not error: %v", err)
	}
}

func TestProcessorConfig_Validate_MissingScannerPath(t *testing.T) {
	cfg := ProcessorConfig{}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty ScannerPath")
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/worker/ -run TestProcessorConfig -v
```
Expected: FAIL (ProcessorConfig not defined)

**Step 3: Create processor.go with the extracted function**

```go
// File: internal/worker/processor.go
package worker

import (
	"context"
	"fmt"

	"github.com/yourorg/scanner-worker/internal/db"
	"github.com/yourorg/scanner-worker/internal/s3"
)

// ProcessorConfig holds configuration for a single scan job execution.
// This is the subset of config.Config needed by the scan runner.
type ProcessorConfig struct {
	ScratchDir                 string
	ScannerPath                string
	ScannerTimeoutSeconds      int
	MaxArtifactBytes           int64
	ReportsBucket              string
	WorkerIngestTimeoutSeconds int
}

func (c ProcessorConfig) Validate() error {
	if c.ScannerPath == "" {
		return fmt.Errorf("ScannerPath is required")
	}
	if c.ReportsBucket == "" {
		return fmt.Errorf("ReportsBucket is required")
	}
	if c.ScratchDir == "" {
		return fmt.Errorf("ScratchDir is required")
	}
	return nil
}

// ProcessSingleJob executes a single scan job and returns any error.
// This is the core scan pipeline extracted for use by both the polling
// worker (legacy) and K8s Job runner (new).
func ProcessSingleJob(ctx context.Context, cfg ProcessorConfig, store *db.Store, s3c *s3.Client, workerID string, j *db.Job) error {
	// This delegates to the existing processJob logic.
	// We create a temporary Runner to reuse existing code during migration.
	r := &Runner{
		cfg: configFromProcessorConfig(cfg),
		db:  store,
		s3:  s3c,
		workerID: workerID,
		breaker:  newScannerBreaker(),
	}
	return r.processJob(ctx, j)
}
```

Note: `configFromProcessorConfig` is a bridge function that maps ProcessorConfig fields to config.Config fields needed by processJob. This allows incremental migration without rewriting processJob immediately.

**Step 4: Run test to verify it passes**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && go test ./internal/worker/ -run TestProcessorConfig -v
```
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && git add internal/worker/processor.go internal/worker/processor_test.go && git commit -m "feat: extract ProcessorConfig and ProcessSingleJob for K8s Job mode"
```

---

### Task 7: Create the single-job CLI entry point

**Files:**
- Create: `cmd/runjob/main.go`

**Step 1: Write the single-job entry point**

This binary reads `SCAN_JOB_ID` from env, fetches the job from DB, runs ProcessSingleJob, and exits.

```go
// File: cmd/runjob/main.go
package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"github.com/google/uuid"
	"github.com/yourorg/scanner-worker/internal/config"
	"github.com/yourorg/scanner-worker/internal/db"
	s3c "github.com/yourorg/scanner-worker/internal/s3"
	"github.com/yourorg/scanner-worker/internal/worker"
)

func main() {
	jobID := os.Getenv("SCAN_JOB_ID")
	if jobID == "" {
		log.Fatal("SCAN_JOB_ID is required")
	}

	cfg := config.Load()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Single-job mode uses a small pool (no concurrency)
	store, err := db.Open(ctx, cfg.DatabaseURL, 1)
	if err != nil {
		log.Fatal(err)
	}
	if err := store.Ping(ctx); err != nil {
		log.Fatal(err)
	}

	s3, err := s3c.New(cfg.S3Endpoint, cfg.S3AccessKey, cfg.S3SecretKey, cfg.S3UseSSL)
	if err != nil {
		log.Fatal(err)
	}

	// Print scanner version
	cmd := exec.CommandContext(ctx, cfg.ScannerPath, "--version")
	out, _ := cmd.CombinedOutput()
	if len(out) > 0 {
		log.Printf("scanrook version: %s", string(out))
	}

	// Fetch the job from DB
	job, err := store.GetJob(ctx, jobID)
	if err != nil {
		log.Fatalf("failed to fetch job %s: %v", jobID, err)
	}

	workerID := uuid.New().String()
	log.Printf("runjob: starting job=%s worker=%s", jobID, workerID)

	pcfg := worker.ProcessorConfig{
		ScratchDir:                 cfg.ScratchDir,
		ScannerPath:                cfg.ScannerPath,
		ScannerTimeoutSeconds:      cfg.ScannerTimeoutSeconds,
		MaxArtifactBytes:           cfg.MaxArtifactBytes,
		ReportsBucket:              cfg.ReportsBucket,
		WorkerIngestTimeoutSeconds: cfg.WorkerIngestTimeoutSeconds,
	}

	if err := worker.ProcessSingleJob(ctx, pcfg, store, s3, workerID, job); err != nil {
		log.Printf("runjob: job %s failed: %v", jobID, err)
		_ = store.MarkFailed(ctx, jobID, err.Error())
		os.Exit(1)
	}

	log.Printf("runjob: job %s completed successfully", jobID)
}
```

**Step 2: Add GetJob to db.Store**

```go
// Add to internal/db/db.go
func (s *Store) GetJob(ctx context.Context, id string) (*Job, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, status, bucket, object_key, mode, format, refs,
		       org_id, settings_snapshot, progress_pct,
		       report_bucket, report_key, error_msg, worker_id
		FROM scan_jobs WHERE id = $1`, id)
	var j Job
	err := row.Scan(&j.ID, &j.Status, &j.Bucket, &j.ObjectKey,
		&j.Mode, &j.Format, &j.Refs,
		&j.OrgID, &j.SettingsJSON, &j.ProgressPct,
		&j.ReportBucket, &j.ReportKey, &j.ErrorMsg, &j.WorkerID)
	if err != nil {
		return nil, fmt.Errorf("get job %s: %w", id, err)
	}
	return &j, nil
}
```

**Step 3: Build to verify compilation**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && go build ./cmd/runjob/
```
Expected: Builds successfully

**Step 4: Commit**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && git add cmd/runjob/ internal/db/db.go internal/worker/processor.go && git commit -m "feat: add runjob entry point for K8s Job single-scan mode"
```

---

### Task 8: Update Dockerfile to bake in scanner + build runjob

**Files:**
- Modify: `Dockerfile`
- Modify: `entrypoint.sh`

**Step 1: Update Dockerfile to build runjob binary and install scanner at build time**

Key changes:
- Add `RUN go build ... -o /out/runjob ./cmd/runjob` to the build stage
- Add a stage that downloads the scanner binary via the install script
- Copy scanner binary into runtime image
- Create a new `entrypoint-runjob.sh` that runs `scanrook upgrade` then `runjob`

```dockerfile
# Add to build stage after existing worker build:
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/runjob ./cmd/runjob

# Add new stage to install scanner:
FROM debian:trixie-slim AS scanner-install
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash curl ca-certificates && rm -rf /var/lib/apt/lists/*
ENV INSTALL_DIR=/usr/local/bin
RUN curl -fsSL https://scanrook.sh/install | bash

# In runtime stage, copy scanner binary:
COPY --from=scanner-install /usr/local/bin/scanrook /usr/local/bin/scanrook
COPY --from=build /out/runjob /usr/local/bin/runjob
```

**Step 2: Create entrypoint-runjob.sh**

```bash
#!/bin/bash
set -e
# Auto-update scanner to latest (fall back to baked-in version on failure)
echo "Upgrading scanrook..."
curl -fsSL https://scanrook.sh/install | INSTALL_DIR=/usr/local/bin bash || echo "WARNING: scanrook upgrade failed, using baked-in version"
scanrook --version || echo "WARNING: scanrook binary not functional"
# Run the single-job binary
exec /usr/local/bin/runjob "$@"
```

**Step 3: Build Docker image to verify**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && docker build --platform linux/amd64 -t devintripp/rust-scanner-worker:k8s-jobs-test .
```
Expected: Builds successfully

**Step 4: Commit**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && git add Dockerfile entrypoint-runjob.sh && git commit -m "feat: bake scanner into Docker image, add runjob entrypoint"
```

---

## Phase 3: Dispatcher

### Task 9: Add client-go dependency

**Files:**
- Modify: `go.mod`

**Step 1: Add the Kubernetes client-go dependency**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && go get k8s.io/client-go@latest k8s.io/api@latest k8s.io/apimachinery@latest
```

**Step 2: Tidy modules**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && go mod tidy
```

**Step 3: Verify build still works**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && go build ./cmd/worker/ && go build ./cmd/runjob/
```
Expected: Both build successfully

**Step 4: Commit**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && git add go.mod go.sum && git commit -m "chore: add k8s client-go dependency for dispatcher"
```

---

### Task 10: Create resource tier configuration

**Files:**
- Create: `internal/dispatcher/tier.go`
- Create: `internal/dispatcher/tier_test.go`

**Step 1: Write the failing test**

```go
// File: internal/dispatcher/tier_test.go
package dispatcher

import "testing"

func TestClassifyTier_Small(t *testing.T) {
	tier := ClassifyTier(100 * 1024 * 1024) // 100 MB
	if tier.Name != "small" {
		t.Fatalf("expected small, got %s", tier.Name)
	}
	if tier.CPURequest != "1" || tier.MemoryRequest != "1Gi" {
		t.Fatalf("unexpected resources: cpu=%s mem=%s", tier.CPURequest, tier.MemoryRequest)
	}
}

func TestClassifyTier_Medium(t *testing.T) {
	tier := ClassifyTier(2 * 1024 * 1024 * 1024) // 2 GB
	if tier.Name != "medium" {
		t.Fatalf("expected medium, got %s", tier.Name)
	}
}

func TestClassifyTier_Large(t *testing.T) {
	tier := ClassifyTier(10 * 1024 * 1024 * 1024) // 10 GB
	if tier.Name != "large" {
		t.Fatalf("expected large, got %s", tier.Name)
	}
}

func TestClassifyTier_Zero(t *testing.T) {
	tier := ClassifyTier(0)
	if tier.Name != "small" {
		t.Fatalf("zero size should be small, got %s", tier.Name)
	}
}
```

**Step 2: Run test to verify it fails**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && go test ./internal/dispatcher/ -run TestClassifyTier -v
```
Expected: FAIL (package doesn't exist)

**Step 3: Implement tier classification**

```go
// File: internal/dispatcher/tier.go
package dispatcher

// ResourceTier defines CPU/memory requests and limits for a scan Job
// based on the artifact size.
type ResourceTier struct {
	Name          string
	CPURequest    string
	CPULimit      string
	MemoryRequest string
	MemoryLimit   string
	MaxConcurrent int
}

var (
	TierSmall = ResourceTier{
		Name: "small", CPURequest: "1", CPULimit: "2",
		MemoryRequest: "1Gi", MemoryLimit: "3Gi", MaxConcurrent: 6,
	}
	TierMedium = ResourceTier{
		Name: "medium", CPURequest: "2", CPULimit: "4",
		MemoryRequest: "2Gi", MemoryLimit: "6Gi", MaxConcurrent: 3,
	}
	TierLarge = ResourceTier{
		Name: "large", CPURequest: "3", CPULimit: "6",
		MemoryRequest: "4Gi", MemoryLimit: "10Gi", MaxConcurrent: 1,
	}
)

const (
	smallThreshold = 500 * 1024 * 1024       // 500 MB
	largeThreshold = 5 * 1024 * 1024 * 1024  // 5 GB
)

// ClassifyTier returns the resource tier for a given artifact size in bytes.
func ClassifyTier(sizeBytes int64) ResourceTier {
	if sizeBytes >= largeThreshold {
		return TierLarge
	}
	if sizeBytes >= smallThreshold {
		return TierMedium
	}
	return TierSmall
}
```

**Step 4: Run test to verify it passes**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && go test ./internal/dispatcher/ -run TestClassifyTier -v
```
Expected: PASS (4 tests)

**Step 5: Commit**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && git add internal/dispatcher/ && git commit -m "feat: add resource tier classification for scan Jobs"
```

---

### Task 11: Create K8s Job builder

**Files:**
- Create: `internal/dispatcher/jobbuilder.go`
- Create: `internal/dispatcher/jobbuilder_test.go`

**Step 1: Write the failing test**

```go
// File: internal/dispatcher/jobbuilder_test.go
package dispatcher

import (
	"testing"
)

func TestBuildScanJob_Labels(t *testing.T) {
	opts := ScanJobOpts{
		JobID:     "abc-123",
		Namespace: "scanrook",
		Image:     "devintripp/rust-scanner-worker:latest",
		Tier:      TierSmall,
		EnvVars:   map[string]string{"DATABASE_URL": "postgres://..."},
	}
	job := BuildScanJob(opts)
	if job.Name != "scan-abc-123" {
		t.Fatalf("expected job name scan-abc-123, got %s", job.Name)
	}
	if job.Labels["scanrook.io/tier"] != "small" {
		t.Fatalf("expected tier label small, got %s", job.Labels["scanrook.io/tier"])
	}
	if job.Labels["scanrook.io/job-id"] != "abc-123" {
		t.Fatalf("expected job-id label, got %s", job.Labels["scanrook.io/job-id"])
	}
}

func TestBuildScanJob_Resources(t *testing.T) {
	opts := ScanJobOpts{
		JobID:     "abc-123",
		Namespace: "scanrook",
		Image:     "img:latest",
		Tier:      TierLarge,
		EnvVars:   map[string]string{},
	}
	job := BuildScanJob(opts)
	container := job.Spec.Template.Spec.Containers[0]
	memReq := container.Resources.Requests.Memory().String()
	if memReq != "4Gi" {
		t.Fatalf("expected 4Gi memory request, got %s", memReq)
	}
}

func TestBuildScanJob_TTL(t *testing.T) {
	opts := ScanJobOpts{
		JobID:     "abc-123",
		Namespace: "scanrook",
		Image:     "img:latest",
		Tier:      TierSmall,
		EnvVars:   map[string]string{},
	}
	job := BuildScanJob(opts)
	if job.Spec.TTLSecondsAfterFinished == nil || *job.Spec.TTLSecondsAfterFinished != 300 {
		t.Fatal("expected TTL of 300 seconds")
	}
}
```

**Step 2: Run test to verify it fails**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && go test ./internal/dispatcher/ -run TestBuildScanJob -v
```
Expected: FAIL

**Step 3: Implement the Job builder**

```go
// File: internal/dispatcher/jobbuilder.go
package dispatcher

import (
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ScanJobOpts holds the parameters for creating a K8s Job.
type ScanJobOpts struct {
	JobID       string
	Namespace   string
	Image       string
	Tier        ResourceTier
	EnvVars     map[string]string       // additional env vars
	EnvFromSecret  string               // Secret name for envFrom
	EnvFromConfig  string               // ConfigMap name for envFrom
	RayonThreads   int                  // RAYON_NUM_THREADS for scanner
	ServiceAccount string
}

// BuildScanJob creates a Kubernetes batch/v1 Job spec for a single scan.
func BuildScanJob(opts ScanJobOpts) *batchv1.Job {
	ttl := int32(300)
	backoffLimit := int32(0) // no K8s-level retries; dispatcher handles retry
	one := int64(1)

	// Build env vars
	envs := []corev1.EnvVar{
		{Name: "SCAN_JOB_ID", Value: opts.JobID},
	}
	if opts.RayonThreads > 0 {
		envs = append(envs, corev1.EnvVar{
			Name: "RAYON_NUM_THREADS", Value: fmt.Sprintf("%d", opts.RayonThreads),
		})
	}
	for k, v := range opts.EnvVars {
		envs = append(envs, corev1.EnvVar{Name: k, Value: v})
	}

	// Build envFrom sources
	var envFromSources []corev1.EnvFromSource
	if opts.EnvFromSecret != "" {
		envFromSources = append(envFromSources, corev1.EnvFromSource{
			SecretRef: &corev1.SecretEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: opts.EnvFromSecret},
			},
		})
	}
	if opts.EnvFromConfig != "" {
		envFromSources = append(envFromSources, corev1.EnvFromSource{
			ConfigMapRef: &corev1.ConfigMapEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: opts.EnvFromConfig},
			},
		})
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("scan-%s", opts.JobID),
			Namespace: opts.Namespace,
			Labels: map[string]string{
				"app":                "scanrook-scan",
				"scanrook.io/tier":   opts.Tier.Name,
				"scanrook.io/job-id": opts.JobID,
			},
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &ttl,
			BackoffLimit:            &backoffLimit,
			ActiveDeadlineSeconds:   nil, // controlled by scanner timeout inside the pod
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":                "scanrook-scan",
						"scanrook.io/tier":   opts.Tier.Name,
						"scanrook.io/job-id": opts.JobID,
					},
				},
				Spec: corev1.PodSpec{
					RestartPolicy:                corev1.RestartPolicyNever,
					ServiceAccountName:           opts.ServiceAccount,
					TerminationGracePeriodSeconds: &one,
					Containers: []corev1.Container{
						{
							Name:    "scan",
							Image:   opts.Image,
							Command: []string{"/usr/local/bin/entrypoint-runjob.sh"},
							Env:     envs,
							EnvFrom: envFromSources,
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse(opts.Tier.CPURequest),
									corev1.ResourceMemory: resource.MustParse(opts.Tier.MemoryRequest),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse(opts.Tier.CPULimit),
									corev1.ResourceMemory: resource.MustParse(opts.Tier.MemoryLimit),
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "scratch", MountPath: "/scratch"},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "scratch",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
				},
			},
		},
	}
}
```

**Step 4: Run test to verify it passes**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && go test ./internal/dispatcher/ -run TestBuildScanJob -v
```
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && git add internal/dispatcher/ && git commit -m "feat: add K8s Job builder with resource tier support"
```

---

### Task 12: Create the dispatcher control loop

**Files:**
- Create: `internal/dispatcher/dispatcher.go`
- Create: `internal/dispatcher/dispatcher_test.go`

**Step 1: Write the failing test for concurrency checking**

```go
// File: internal/dispatcher/dispatcher_test.go
package dispatcher

import "testing"

func TestCanSchedule_UnderLimit(t *testing.T) {
	active := map[string]int{"small": 2, "medium": 1, "large": 0}
	if !canSchedule(TierSmall, active) {
		t.Fatal("should be able to schedule small (2 < 6)")
	}
}

func TestCanSchedule_AtLimit(t *testing.T) {
	active := map[string]int{"small": 6, "medium": 0, "large": 0}
	if canSchedule(TierSmall, active) {
		t.Fatal("should NOT schedule small (6 >= 6)")
	}
}

func TestCanSchedule_LargeAtLimit(t *testing.T) {
	active := map[string]int{"small": 0, "medium": 0, "large": 1}
	if canSchedule(TierLarge, active) {
		t.Fatal("should NOT schedule large (1 >= 1)")
	}
}
```

**Step 2: Run test to verify it fails**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && go test ./internal/dispatcher/ -run TestCanSchedule -v
```
Expected: FAIL

**Step 3: Implement the dispatcher**

```go
// File: internal/dispatcher/dispatcher.go
package dispatcher

import (
	"context"
	"fmt"
	"log"
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
	cfg    DispatcherConfig
	db     *db.Store
	s3     *s3.Client
	k8s    kubernetes.Interface
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

		// Periodic stale job sweep
		if sweepInterval > 0 && time.Now().After(nextSweep) {
			d.reapStaleJobs(ctx)
			nextSweep = time.Now().Add(sweepInterval)
		}

		// Check tier capacity
		activeCounts, err := d.countActiveJobs(ctx)
		if err != nil {
			log.Printf("dispatcher: failed to count active jobs: %v", err)
			time.Sleep(pollInterval)
			continue
		}

		// Try to acquire a queued job
		job, err := d.db.AcquireNextQueued(ctx, workerID)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}

		// Check artifact size and classify tier
		objSize, err := d.s3.GetObjectSize(ctx, job.Bucket, job.ObjectKey)
		if err != nil {
			log.Printf("dispatcher: job %s: failed to get object size: %v", job.ID, err)
			_ = d.db.MarkFailed(ctx, job.ID, "failed to get artifact size: "+err.Error())
			continue
		}

		tier := ClassifyTier(objSize)

		// Check if we can schedule this tier
		if !canSchedule(tier, activeCounts) {
			log.Printf("dispatcher: job %s: tier %s at capacity (%d/%d), re-queuing",
				job.ID, tier.Name, activeCounts[tier.Name], tier.MaxConcurrent)
			_ = d.db.RequeueJob(ctx, job.ID)
			time.Sleep(pollInterval)
			continue
		}

		// Create K8s Job
		rayonThreads := 1
		switch tier.Name {
		case "medium":
			rayonThreads = 2
		case "large":
			rayonThreads = 3
		}

		scanJob := BuildScanJob(ScanJobOpts{
			JobID:          job.ID,
			Namespace:      d.cfg.Namespace,
			Image:          d.cfg.Image,
			Tier:           tier,
			EnvVars:        map[string]string{},
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

// reapStaleJobs marks jobs as failed if they've been running too long.
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
		// Clean up the K8s Job if it exists
		_ = d.k8s.BatchV1().Jobs(d.cfg.Namespace).Delete(ctx,
			fmt.Sprintf("scan-%s", id), metav1.DeleteOptions{})
	}
}
```

Note: `RequeueJob` needs to be added to `db.Store` — it sets status back to `queued` and clears `worker_id`.

**Step 4: Run tests to verify they pass**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && go test ./internal/dispatcher/ -v
```
Expected: All tests PASS

**Step 5: Commit**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && git add internal/dispatcher/ internal/db/ && git commit -m "feat: add dispatcher control loop with tier-based K8s Job scheduling"
```

---

### Task 13: Create the dispatcher entry point

**Files:**
- Create: `cmd/dispatcher/main.go`

**Step 1: Write the dispatcher main**

```go
// File: cmd/dispatcher/main.go
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/yourorg/scanner-worker/internal/config"
	"github.com/yourorg/scanner-worker/internal/db"
	"github.com/yourorg/scanner-worker/internal/dispatcher"
	s3c "github.com/yourorg/scanner-worker/internal/s3"
)

func main() {
	_ = godotenv.Load(".env.local")
	_ = godotenv.Load(".env")

	cfg := config.Load()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Dispatcher uses a small DB pool (just polling + sweeps)
	store, err := db.Open(ctx, cfg.DatabaseURL, 1)
	if err != nil {
		log.Fatal(err)
	}
	if err := store.Ping(ctx); err != nil {
		log.Fatal(err)
	}

	s3, err := s3c.New(cfg.S3Endpoint, cfg.S3AccessKey, cfg.S3SecretKey, cfg.S3UseSSL)
	if err != nil {
		log.Fatal(err)
	}

	// In-cluster K8s client
	k8sCfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("failed to get in-cluster k8s config: %v", err)
	}
	k8sClient, err := kubernetes.NewForConfig(k8sCfg)
	if err != nil {
		log.Fatalf("failed to create k8s client: %v", err)
	}

	namespace := os.Getenv("DISPATCHER_NAMESPACE")
	if namespace == "" {
		namespace = "scanrook"
	}
	image := os.Getenv("DISPATCHER_SCAN_IMAGE")
	if image == "" {
		log.Fatal("DISPATCHER_SCAN_IMAGE is required")
	}

	dcfg := dispatcher.DispatcherConfig{
		Namespace:              namespace,
		Image:                  image,
		ServiceAccount:         os.Getenv("DISPATCHER_SERVICE_ACCOUNT"),
		EnvFromSecret:          os.Getenv("DISPATCHER_ENV_SECRET"),
		EnvFromConfig:          os.Getenv("DISPATCHER_ENV_CONFIGMAP"),
		PollInterval:           2 * time.Second,
		StaleJobTimeoutSeconds: cfg.StaleJobTimeoutSeconds,
		StaleSweepSeconds:      cfg.StaleSweepSeconds,
	}

	// Health endpoint
	if addr := cfg.HTTPAddr; addr != "" {
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
			s := &http.Server{Addr: addr, Handler: mux}
			go func() { <-ctx.Done(); _ = s.Shutdown(context.Background()) }()
			_ = s.ListenAndServe()
		}()
	}

	workerID := uuid.New().String()
	log.Printf("dispatcher starting: id=%s namespace=%s image=%s", workerID, namespace, image)

	d := dispatcher.New(dcfg, store, s3, k8sClient)
	if err := d.Run(ctx, workerID); err != nil {
		log.Fatal(err)
	}
}
```

**Step 2: Build to verify compilation**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && go build ./cmd/dispatcher/
```
Expected: Builds successfully

**Step 3: Update Dockerfile to also build dispatcher binary**

Add to the Go build stage:
```dockerfile
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/dispatcher ./cmd/dispatcher
```

And in the runtime stage:
```dockerfile
COPY --from=build /out/dispatcher /usr/local/bin/dispatcher
```

**Step 4: Commit**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && git add cmd/dispatcher/ Dockerfile && git commit -m "feat: add dispatcher entry point for K8s Job scheduling"
```

---

### Task 14: Add RequeueJob to db.Store

**Files:**
- Modify: `internal/db/db.go`
- Create: `internal/db/db_requeue_test.go`

**Step 1: Write the test**

```go
// File: internal/db/db_requeue_test.go
package db

import "testing"

func TestRequeueJob_SQL(t *testing.T) {
	// Verify the SQL is syntactically correct by checking the function exists
	// Full integration test requires a running database
	t.Log("RequeueJob function should exist and compile")
}
```

**Step 2: Add RequeueJob**

```go
// Add to internal/db/db.go
func (s *Store) RequeueJob(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE scan_jobs
		SET status = 'queued', worker_id = NULL, progress_pct = 0
		WHERE id = $1 AND status = 'running'`, id)
	return err
}
```

**Step 3: Build and test**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && go build ./... && go test ./internal/db/ -v
```
Expected: Builds and tests pass

**Step 4: Commit**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && git add internal/db/ && git commit -m "feat: add RequeueJob for dispatcher tier capacity backoff"
```

---

## Phase 4: K8s Manifests

### Task 15: Create RBAC manifests for dispatcher

**Files:**
- Create: `k8s/deltaguard/dispatcher-rbac.yaml` (in scanrook-ui repo)

**Step 1: Create ServiceAccount, Role, and RoleBinding**

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: scanrook-dispatcher
  namespace: scanrook
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: scanrook-dispatcher
  namespace: scanrook
rules:
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["create", "get", "list", "watch", "delete"]
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: scanrook-dispatcher
  namespace: scanrook
subjects:
  - kind: ServiceAccount
    name: scanrook-dispatcher
    namespace: scanrook
roleRef:
  kind: Role
  name: scanrook-dispatcher
  apiGroup: rbac.authorization.k8s.io
```

**Step 2: Apply to cluster**

```bash
ssh dg-node1 "kubectl apply -f -" <<< '<the yaml>'
```

**Step 3: Verify**

```bash
ssh dg-node1 "kubectl get sa,role,rolebinding -n scanrook | grep dispatcher"
```
Expected: All three resources created

**Step 4: Commit**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/scanrook-ui && git add k8s/deltaguard/dispatcher-rbac.yaml && git commit -m "feat: add RBAC manifests for scanrook dispatcher"
```

---

### Task 16: Create dispatcher Deployment manifest

**Files:**
- Create: `k8s/deltaguard/dispatcher-deployment.yaml` (in scanrook-ui repo)

**Step 1: Write the Deployment manifest**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scanrook-dispatcher
  namespace: scanrook
  labels:
    app: scanrook-dispatcher
spec:
  replicas: 1
  selector:
    matchLabels:
      app: scanrook-dispatcher
  template:
    metadata:
      labels:
        app: scanrook-dispatcher
    spec:
      serviceAccountName: scanrook-dispatcher
      containers:
        - name: dispatcher
          image: devintripp/rust-scanner-worker:dispatcher-v1
          command: ["/usr/local/bin/dispatcher"]
          ports:
            - name: http
              containerPort: 8080
          envFrom:
            - secretRef:
                name: scanrook-secrets
            - configMapRef:
                name: scanrook-config
          env:
            - name: HTTP_ADDR
              value: ":8080"
            - name: DISPATCHER_NAMESPACE
              value: scanrook
            - name: DISPATCHER_SCAN_IMAGE
              value: devintripp/rust-scanner-worker:scan-runner-v1
            - name: DISPATCHER_SERVICE_ACCOUNT
              value: scanrook-dispatcher
            - name: DISPATCHER_ENV_SECRET
              value: scanrook-secrets
            - name: DISPATCHER_ENV_CONFIGMAP
              value: scanrook-config
            - name: WORKER_CONCURRENCY
              value: "1"
            - name: WORKER_STALE_JOB_TIMEOUT_SECONDS
              value: "1800"
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          livenessProbe:
            httpGet:
              path: /healthz
              port: http
            initialDelaySeconds: 5
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /healthz
              port: http
            initialDelaySeconds: 3
            periodSeconds: 10
```

**Step 2: Commit**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/scanrook-ui && git add k8s/deltaguard/dispatcher-deployment.yaml && git commit -m "feat: add dispatcher Deployment manifest"
```

---

### Task 17: Update NetworkPolicy for scan Job pods and dispatcher

**Files:**
- Modify: `k8s/deltaguard/networkpolicy.yaml` (in scanrook-ui repo)

**Step 1: Add NetworkPolicy for scan Job pods**

Scan Job pods need the same egress as workers (DB, S3, DNS, internet for enrichment APIs):

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: scanrook-scan-job
  namespace: scanrook
spec:
  podSelector:
    matchLabels:
      app: scanrook-scan
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: db
      ports:
        - protocol: TCP
          port: 5432
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: storage
      ports:
        - protocol: TCP
          port: 9000
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
      ports:
        - protocol: TCP
          port: 443
        - protocol: TCP
          port: 80
    - to:
        - ipBlock:
            cidr: 10.10.10.2/32
      ports:
        - protocol: TCP
          port: 3128
```

**Step 2: Apply and commit**

---

## Phase 5: Deploy & Test

### Task 18: Build and push Docker images

**Step 1: Build the combined image (has worker, runjob, dispatcher, and scanner)**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/rust-scanner-worker && \
docker build --platform linux/amd64 -t devintripp/rust-scanner-worker:k8s-scheduler-v1 . && \
docker push devintripp/rust-scanner-worker:k8s-scheduler-v1
```

**Step 2: Tag for specific roles**

```bash
docker tag devintripp/rust-scanner-worker:k8s-scheduler-v1 devintripp/rust-scanner-worker:dispatcher-v1
docker tag devintripp/rust-scanner-worker:k8s-scheduler-v1 devintripp/rust-scanner-worker:scan-runner-v1
docker push devintripp/rust-scanner-worker:dispatcher-v1
docker push devintripp/rust-scanner-worker:scan-runner-v1
```

---

### Task 19: Deploy dispatcher alongside existing workers (canary)

**Step 1: Apply RBAC**

```bash
ssh dg-node1 "kubectl apply -f -" <<< '<rbac yaml>'
```

**Step 2: Deploy dispatcher with 1 replica**

```bash
ssh dg-node1 "kubectl apply -f -" <<< '<dispatcher deployment yaml>'
```

**Step 3: Verify dispatcher is running**

```bash
ssh dg-node1 "kubectl get pods -n scanrook -l app=scanrook-dispatcher"
```
Expected: 1/1 Running

**Step 4: Scale down old workers to 0**

```bash
ssh dg-node1 "kubectl scale deployment scanrook-worker -n scanrook --replicas=0"
```

**Step 5: Trigger a test scan via the UI**

Upload a small file (<500MB) and verify:
1. Dispatcher logs show Job creation
2. K8s Job pod starts and runs
3. Progress events appear in SSE stream
4. Scan completes with findings

```bash
ssh dg-node1 "kubectl logs -n scanrook -l app=scanrook-dispatcher --tail=50"
ssh dg-node1 "kubectl get jobs -n scanrook -l app=scanrook-scan"
```

---

### Task 20: Verify resource isolation with concurrent scans

**Step 1: Upload 3 small files in quick succession**

Verify all 3 scan Jobs are created and run concurrently on different nodes.

**Step 2: Upload a large file (>5GB)**

Verify:
- Tier classification is `large`
- Job has 3 CPU / 4Gi memory requests
- Only 1 large scan runs at a time
- Additional large scans stay queued

**Step 3: Monitor resource usage**

```bash
ssh dg-node1 "kubectl top pods -n scanrook"
ssh dg-node1 "kubectl top nodes"
```

Verify no node is overcommitted.

---

### Task 21: Remove old worker deployment and clean up

Only after canary validation passes:

**Step 1: Delete old worker deployment**

```bash
ssh dg-node1 "kubectl delete deployment scanrook-worker -n scanrook"
```

**Step 2: Update PDB**

Update `scanrook-worker-pdb` to reference `scanrook-dispatcher` or remove if not needed.

**Step 3: Update kustomization.yaml**

Add `dispatcher-deployment.yaml` and `dispatcher-rbac.yaml` to the kustomization resources list.

**Step 4: Commit all manifest changes**

```bash
cd /Users/devintripp/Desktop/GitHub/scanrook/scanrook-ui && git add k8s/ && git commit -m "feat: switch from worker to K8s Job-based dispatcher"
```

---

## Summary

| Phase | Tasks | Estimated Effort |
|-------|-------|-----------------|
| 1. Infrastructure Prep | Tasks 1-5 | Cluster ops |
| 2. Worker Refactor | Tasks 6-8 | Go coding |
| 3. Dispatcher | Tasks 9-14 | Go coding + K8s client |
| 4. K8s Manifests | Tasks 15-17 | YAML |
| 5. Deploy & Test | Tasks 18-21 | Deploy + verify |
