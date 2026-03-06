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
	cpuReq := container.Resources.Requests.Cpu().String()
	if cpuReq != "3" {
		t.Fatalf("expected 3 cpu request, got %s", cpuReq)
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

func TestBuildScanJob_BackoffLimit(t *testing.T) {
	opts := ScanJobOpts{
		JobID:     "abc-123",
		Namespace: "scanrook",
		Image:     "img:latest",
		Tier:      TierSmall,
		EnvVars:   map[string]string{},
	}
	job := BuildScanJob(opts)
	if job.Spec.BackoffLimit == nil || *job.Spec.BackoffLimit != 0 {
		t.Fatal("expected backoffLimit of 0")
	}
}

func TestBuildScanJob_ScanJobID_Env(t *testing.T) {
	opts := ScanJobOpts{
		JobID:     "xyz-789",
		Namespace: "scanrook",
		Image:     "img:latest",
		Tier:      TierSmall,
		EnvVars:   map[string]string{},
	}
	job := BuildScanJob(opts)
	container := job.Spec.Template.Spec.Containers[0]
	found := false
	for _, env := range container.Env {
		if env.Name == "SCAN_JOB_ID" && env.Value == "xyz-789" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected SCAN_JOB_ID=xyz-789 in container env")
	}
}

func TestBuildScanJob_Namespace(t *testing.T) {
	opts := ScanJobOpts{
		JobID:     "ns-test",
		Namespace: "custom-ns",
		Image:     "img:latest",
		Tier:      TierMedium,
		EnvVars:   map[string]string{},
	}
	job := BuildScanJob(opts)
	if job.Namespace != "custom-ns" {
		t.Fatalf("expected namespace custom-ns, got %s", job.Namespace)
	}
}

func TestBuildScanJob_EnvFromSecret(t *testing.T) {
	opts := ScanJobOpts{
		JobID:         "sec-test",
		Namespace:     "scanrook",
		Image:         "img:latest",
		Tier:          TierSmall,
		EnvVars:       map[string]string{},
		EnvFromSecret: "scanrook-worker-env",
	}
	job := BuildScanJob(opts)
	container := job.Spec.Template.Spec.Containers[0]
	if len(container.EnvFrom) == 0 {
		t.Fatal("expected envFrom sources")
	}
	found := false
	for _, ef := range container.EnvFrom {
		if ef.SecretRef != nil && ef.SecretRef.Name == "scanrook-worker-env" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected secretRef for scanrook-worker-env")
	}
}

func TestBuildScanJob_EnvFromConfigMap(t *testing.T) {
	opts := ScanJobOpts{
		JobID:         "cm-test",
		Namespace:     "scanrook",
		Image:         "img:latest",
		Tier:          TierSmall,
		EnvVars:       map[string]string{},
		EnvFromConfig: "scanrook-config",
	}
	job := BuildScanJob(opts)
	container := job.Spec.Template.Spec.Containers[0]
	found := false
	for _, ef := range container.EnvFrom {
		if ef.ConfigMapRef != nil && ef.ConfigMapRef.Name == "scanrook-config" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected configMapRef for scanrook-config")
	}
}

func TestBuildScanJob_RayonThreads(t *testing.T) {
	opts := ScanJobOpts{
		JobID:        "rayon-test",
		Namespace:    "scanrook",
		Image:        "img:latest",
		Tier:         TierSmall,
		EnvVars:      map[string]string{},
		RayonThreads: 4,
	}
	job := BuildScanJob(opts)
	container := job.Spec.Template.Spec.Containers[0]
	found := false
	for _, env := range container.Env {
		if env.Name == "RAYON_NUM_THREADS" && env.Value == "4" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected RAYON_NUM_THREADS=4 in container env")
	}
}

func TestBuildScanJob_ServiceAccount(t *testing.T) {
	opts := ScanJobOpts{
		JobID:          "sa-test",
		Namespace:      "scanrook",
		Image:          "img:latest",
		Tier:           TierSmall,
		EnvVars:        map[string]string{},
		ServiceAccount: "scan-runner",
	}
	job := BuildScanJob(opts)
	if job.Spec.Template.Spec.ServiceAccountName != "scan-runner" {
		t.Fatalf("expected service account scan-runner, got %s", job.Spec.Template.Spec.ServiceAccountName)
	}
}

func TestBuildScanJob_ScratchVolume(t *testing.T) {
	opts := ScanJobOpts{
		JobID:     "vol-test",
		Namespace: "scanrook",
		Image:     "img:latest",
		Tier:      TierSmall,
		EnvVars:   map[string]string{},
	}
	job := BuildScanJob(opts)
	spec := job.Spec.Template.Spec

	// Check volume exists
	foundVol := false
	for _, v := range spec.Volumes {
		if v.Name == "scratch" && v.EmptyDir != nil {
			foundVol = true
			break
		}
	}
	if !foundVol {
		t.Fatal("expected scratch emptyDir volume")
	}

	// Check volume mount exists
	container := spec.Containers[0]
	foundMount := false
	for _, vm := range container.VolumeMounts {
		if vm.Name == "scratch" && vm.MountPath == "/scratch" {
			foundMount = true
			break
		}
	}
	if !foundMount {
		t.Fatal("expected scratch volume mount at /scratch")
	}
}

func TestBuildScanJob_PodLabelsMatchJob(t *testing.T) {
	opts := ScanJobOpts{
		JobID:     "label-test",
		Namespace: "scanrook",
		Image:     "img:latest",
		Tier:      TierMedium,
		EnvVars:   map[string]string{},
	}
	job := BuildScanJob(opts)
	podLabels := job.Spec.Template.Labels
	if podLabels["app"] != "scanrook-scan" {
		t.Fatalf("expected pod app label scanrook-scan, got %s", podLabels["app"])
	}
	if podLabels["scanrook.io/tier"] != "medium" {
		t.Fatalf("expected pod tier label medium, got %s", podLabels["scanrook.io/tier"])
	}
	if podLabels["scanrook.io/job-id"] != "label-test" {
		t.Fatalf("expected pod job-id label label-test, got %s", podLabels["scanrook.io/job-id"])
	}
}

func TestBuildScanJob_RestartPolicyNever(t *testing.T) {
	opts := ScanJobOpts{
		JobID:     "restart-test",
		Namespace: "scanrook",
		Image:     "img:latest",
		Tier:      TierSmall,
		EnvVars:   map[string]string{},
	}
	job := BuildScanJob(opts)
	if job.Spec.Template.Spec.RestartPolicy != "Never" {
		t.Fatalf("expected RestartPolicy Never, got %s", job.Spec.Template.Spec.RestartPolicy)
	}
}

func TestBuildScanJob_Entrypoint(t *testing.T) {
	opts := ScanJobOpts{
		JobID:     "cmd-test",
		Namespace: "scanrook",
		Image:     "img:latest",
		Tier:      TierSmall,
		EnvVars:   map[string]string{},
	}
	job := BuildScanJob(opts)
	container := job.Spec.Template.Spec.Containers[0]
	if len(container.Command) != 1 || container.Command[0] != "/usr/local/bin/entrypoint-runjob.sh" {
		t.Fatalf("expected command /usr/local/bin/entrypoint-runjob.sh, got %v", container.Command)
	}
}

func TestBuildScanJob_MediumTierResources(t *testing.T) {
	opts := ScanJobOpts{
		JobID:     "med-test",
		Namespace: "scanrook",
		Image:     "img:latest",
		Tier:      TierMedium,
		EnvVars:   map[string]string{},
	}
	job := BuildScanJob(opts)
	container := job.Spec.Template.Spec.Containers[0]
	cpuReq := container.Resources.Requests.Cpu().String()
	if cpuReq != "2" {
		t.Fatalf("expected 2 cpu request for medium, got %s", cpuReq)
	}
	memReq := container.Resources.Requests.Memory().String()
	if memReq != "2Gi" {
		t.Fatalf("expected 2Gi memory request for medium, got %s", memReq)
	}
	cpuLim := container.Resources.Limits.Cpu().String()
	if cpuLim != "4" {
		t.Fatalf("expected 4 cpu limit for medium, got %s", cpuLim)
	}
	memLim := container.Resources.Limits.Memory().String()
	if memLim != "6Gi" {
		t.Fatalf("expected 6Gi memory limit for medium, got %s", memLim)
	}
}
