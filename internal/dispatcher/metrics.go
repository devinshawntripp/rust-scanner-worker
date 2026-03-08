package dispatcher

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// JobsDispatched counts total jobs dispatched, labeled by tier.
	JobsDispatched = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "scanrook_jobs_dispatched_total",
		Help: "Total scan jobs dispatched to K8s, by tier.",
	}, []string{"tier"})

	// JobsFailed counts total jobs that failed, labeled by reason.
	JobsFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "scanrook_jobs_failed_total",
		Help: "Total scan jobs that failed, by reason.",
	}, []string{"reason"})

	// JobsCompleted counts total completed jobs.
	JobsCompleted = promauto.NewCounter(prometheus.CounterOpts{
		Name: "scanrook_jobs_completed_total",
		Help: "Total scan jobs completed successfully.",
	})

	// JobsRequeued counts how many times jobs were re-queued due to capacity.
	JobsRequeued = promauto.NewCounter(prometheus.CounterOpts{
		Name: "scanrook_jobs_requeued_total",
		Help: "Total times jobs were re-queued due to tier capacity limits.",
	})

	// ActiveScanPods gauge of currently active scan pods by tier.
	ActiveScanPods = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "scanrook_active_scan_pods",
		Help: "Number of currently active scan pods, by tier.",
	}, []string{"tier"})

	// JobsStaleFailed counts jobs reaped by stale sweep.
	JobsStaleFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "scanrook_jobs_stale_failed_total",
		Help: "Total jobs marked failed by stale sweep.",
	})

	// JobsCancelled counts cancelled jobs.
	JobsCancelled = promauto.NewCounter(prometheus.CounterOpts{
		Name: "scanrook_jobs_cancelled_total",
		Help: "Total jobs cancelled by user request.",
	})
)
