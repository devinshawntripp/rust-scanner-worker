package dispatcher

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RegisterHandlers adds job management HTTP endpoints to the given mux.
func (d *Dispatcher) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/jobs/", func(w http.ResponseWriter, r *http.Request) {
		// Parse: /jobs/{id}/cancel or /jobs/{id}/requeue
		path := strings.TrimPrefix(r.URL.Path, "/jobs/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) != 2 {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		jobID := parts[0]
		action := parts[1]

		switch {
		case r.Method == http.MethodPost && action == "cancel":
			d.handleCancelJob(w, r, jobID)
		case r.Method == http.MethodPost && action == "requeue":
			d.handleRequeueJob(w, r, jobID)
		default:
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		}
	})
}

func (d *Dispatcher) handleCancelJob(w http.ResponseWriter, r *http.Request, jobID string) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Check current job state
	job, err := d.db.GetJob(ctx, jobID)
	if err != nil {
		log.Printf("cancel: job %s lookup failed: %v", jobID, err)
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}

	if job.Status != "queued" && job.Status != "running" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error":  "job is not cancellable",
			"status": job.Status,
		})
		return
	}

	wasRunning := job.Status == "running"

	// Cancel in DB
	cancelled, err := d.db.CancelJob(ctx, jobID)
	if err != nil {
		log.Printf("cancel: job %s db cancel failed: %v", jobID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cancel failed"})
		return
	}
	if !cancelled {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "job already completed or cancelled"})
		return
	}

	// Delete K8s Job if it was running
	if wasRunning {
		k8sJobName := fmt.Sprintf("scan-%s", jobID)
		err := d.k8s.BatchV1().Jobs(d.cfg.Namespace).Delete(ctx,
			k8sJobName, metav1.DeleteOptions{})
		if err != nil {
			log.Printf("cancel: job %s: K8s Job delete failed (may already be gone): %v", jobID, err)
		} else {
			log.Printf("cancel: job %s: deleted K8s Job %s", jobID, k8sJobName)
		}
	}

	JobsCancelled.Inc()
	log.Printf("cancel: job %s cancelled (was %s)", jobID, job.Status)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled", "id": jobID})
}

func (d *Dispatcher) handleRequeueJob(w http.ResponseWriter, r *http.Request, jobID string) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	requeued, err := d.db.RequeueCancelledOrFailed(ctx, jobID)
	if err != nil {
		log.Printf("requeue: job %s failed: %v", jobID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "requeue failed"})
		return
	}
	if !requeued {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "job is not in a requeueable state"})
		return
	}

	log.Printf("requeue: job %s re-queued", jobID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "queued", "id": jobID})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
