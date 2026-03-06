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
	smallThreshold int64 = 500 * 1024 * 1024      // 500 MB
	largeThreshold int64 = 5 * 1024 * 1024 * 1024  // 5 GB
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
