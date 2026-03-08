package dispatcher

import (
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func strPtr(s string) *string { return &s }

// RegistryInitOpts configures the registry-puller init container.
type RegistryInitOpts struct {
	PullerImage   string // e.g. devintripp/scanrook-registry-puller:v1
	RegistryImage string // e.g. ghcr.io/org/app:v1.2.3
	Username      string // optional
	Token         string // optional (decrypted plaintext)
}

// ScanJobOpts holds the parameters for creating a K8s Job.
type ScanJobOpts struct {
	JobID          string
	Namespace      string
	Image          string
	Tier           ResourceTier
	EnvVars        map[string]string
	EnvFromSecret  string
	EnvFromConfig  string
	RayonThreads   int
	ServiceAccount string
	Registry       *RegistryInitOpts // non-nil for registry scan jobs
}

// BuildScanJob creates a Kubernetes batch/v1 Job spec for a single scan.
func BuildScanJob(opts ScanJobOpts) *batchv1.Job {
	ttl := int32(300)
	backoffLimit := int32(0)
	one := int64(1)

	envs := []corev1.EnvVar{
		{Name: "SCAN_JOB_ID", Value: opts.JobID},
	}
	if opts.RayonThreads > 0 {
		envs = append(envs, corev1.EnvVar{
			Name:  "RAYON_NUM_THREADS",
			Value: fmt.Sprintf("%d", opts.RayonThreads),
		})
	}
	for k, v := range opts.EnvVars {
		envs = append(envs, corev1.EnvVar{Name: k, Value: v})
	}

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

	labels := map[string]string{
		"app":                "scanrook-scan",
		"scanrook.io/tier":   opts.Tier.Name,
		"scanrook.io/job-id": opts.JobID,
	}
	if opts.Registry != nil {
		labels["scanrook.io/source"] = "registry"
	}

	podSpec := corev1.PodSpec{
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           opts.ServiceAccount,
		TerminationGracePeriodSeconds: &one,
		DNSPolicy: corev1.DNSNone,
		DNSConfig: &corev1.PodDNSConfig{
			Nameservers: []string{"10.96.0.10"},
			Searches: []string{
				opts.Namespace + ".svc.cluster.local",
				"svc.cluster.local",
				"cluster.local",
			},
			Options: []corev1.PodDNSConfigOption{
				{Name: "ndots", Value: strPtr("5")},
			},
		},
		Containers: []corev1.Container{
			{
				Name:            "scan",
				Image:           opts.Image,
				ImagePullPolicy: corev1.PullAlways,
				Command:         []string{"/usr/local/bin/entrypoint-runjob.sh"},
				Env:             envs,
				EnvFrom:         envFromSources,
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
	}

	// Inject registry-puller init container for registry scan jobs
	if opts.Registry != nil && opts.Registry.PullerImage != "" {
		initEnvs := []corev1.EnvVar{
			{Name: "SCAN_JOB_ID", Value: opts.JobID},
			{Name: "REGISTRY_IMAGE", Value: opts.Registry.RegistryImage},
		}
		if opts.Registry.Username != "" {
			initEnvs = append(initEnvs, corev1.EnvVar{
				Name: "REGISTRY_USERNAME", Value: opts.Registry.Username,
			})
		}
		if opts.Registry.Token != "" {
			initEnvs = append(initEnvs, corev1.EnvVar{
				Name: "REGISTRY_TOKEN", Value: opts.Registry.Token,
			})
		}
		// Inherit proxy env vars so the puller can reach external registries
		for k, v := range opts.EnvVars {
			initEnvs = append(initEnvs, corev1.EnvVar{Name: k, Value: v})
		}

		// Init container gets S3 credentials from the same secret + config as the scan container
		var initEnvFrom []corev1.EnvFromSource
		if opts.EnvFromSecret != "" {
			initEnvFrom = append(initEnvFrom, corev1.EnvFromSource{
				SecretRef: &corev1.SecretEnvSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: opts.EnvFromSecret},
				},
			})
		}
		if opts.EnvFromConfig != "" {
			initEnvFrom = append(initEnvFrom, corev1.EnvFromSource{
				ConfigMapRef: &corev1.ConfigMapEnvSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: opts.EnvFromConfig},
				},
			})
		}

		podSpec.InitContainers = []corev1.Container{
			{
				Name:            "registry-puller",
				Image:           opts.Registry.PullerImage,
				ImagePullPolicy: corev1.PullAlways,
				Command:         []string{"/usr/local/bin/registry-puller"},
				Env:             initEnvs,
				EnvFrom:         initEnvFrom,
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("500m"),
						corev1.ResourceMemory: resource.MustParse("512Mi"),
					},
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("1"),
						corev1.ResourceMemory: resource.MustParse("2Gi"),
					},
				},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "scratch", MountPath: "/scratch"},
				},
			},
		}
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("scan-%s", opts.JobID),
			Namespace: opts.Namespace,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &ttl,
			BackoffLimit:            &backoffLimit,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: podSpec,
			},
		},
	}
}
