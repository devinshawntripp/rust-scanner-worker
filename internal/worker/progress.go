package worker

import (
	"bufio"
	"context"
	"encoding/json"
    "log"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/yourorg/scanner-worker/internal/db"
	"github.com/yourorg/scanner-worker/internal/model"
)

func derivePct(stage string) int {
	// Very simple stage→% mapping; adjust as your scanner evolves
	switch {
	case strings.Contains(stage, "start"):
		return 5
	case strings.Contains(stage, "download"):
		return 10
	case strings.Contains(stage, "index"):
		return 30
	case strings.Contains(stage, "scan"):
		return 70
	case strings.Contains(stage, "done"):
		return 100
	default:
		return 50
	}
}

func TailProgress(ctx context.Context, st *db.Store, jobID, progressPath string) (stop func()) {
	var stopped atomic.Bool
	go func() {
		defer stopped.Store(true)
        // Wait for the progress file to appear for a short time window
        var f *os.File
        var err error
        for i := 0; i < 40 && ctx.Err() == nil; i++ { // ~4s
            f, err = os.Open(progressPath)
            if err == nil { break }
            time.Sleep(100 * time.Millisecond)
        }
        if f == nil {
            log.Printf("job %s: progress file not found, continuing without tail", jobID)
            return
        }
		defer f.Close()

		r := bufio.NewReader(f)
		for ctx.Err() == nil {
			line, err := r.ReadBytes('\n')
			if len(line) > 0 {
				var evt model.ProgressEvent
				if json.Unmarshal(line, &evt) == nil {
					p := derivePct(evt.Stage)
					_ = st.UpdateProgress(ctx, jobID, p, evt.Stage+": "+evt.Detail)
				}
			}
            if err != nil { time.Sleep(300 * time.Millisecond) }
		}
	}()
	return func() {
		// rely on ctx cancellation
		for !stopped.Load() {
			time.Sleep(50 * time.Millisecond)
		}
	}
}
