package worker

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/yourorg/scanner-worker/internal/db"
	"github.com/yourorg/scanner-worker/internal/model"
)

var ratioRe = regexp.MustCompile(`\b(\d+)\s*/\s*(\d+)\b`)

const (
	// Keep high-cardinality enrich/cache stages from flooding Postgres/UI.
	noisyEventMinInterval     = 3 * time.Second
	progressUpdateMinInterval = 2 * time.Second
)

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func pctFromDetail(detail string, lo, hi int) int {
	m := ratioRe.FindStringSubmatch(detail)
	if len(m) != 3 {
		return (lo + hi) / 2
	}
	cur, errCur := strconv.Atoi(m[1])
	tot, errTot := strconv.Atoi(m[2])
	if errCur != nil || errTot != nil || tot <= 0 {
		return (lo + hi) / 2
	}
	r := float64(cur) / float64(tot)
	if r < 0 {
		r = 0
	}
	if r > 1 {
		r = 1
	}
	return clamp(lo+int(r*float64(hi-lo)), lo, hi)
}

func derivePct(stage, detail string) int {
	s := strings.ToLower(strings.TrimSpace(stage))
	isErr := strings.HasSuffix(s, ".err") || strings.HasSuffix(s, ".error")

	if isErr {
		base := strings.TrimSuffix(strings.TrimSuffix(s, ".error"), ".err")
		// Only terminal scan failure should force 100%.
		if base == "scan" || strings.HasPrefix(base, "scan.") {
			return 100
		}
		s = base
	}

	if s == "scan.done" || s == "scan.summary" {
		return 100
	}

	switch {
	case strings.HasPrefix(s, "scan.start"):
		return 2

	case strings.HasPrefix(s, "iso.detect"), strings.HasPrefix(s, "iso.entries.list"):
		if strings.HasSuffix(s, ".done") {
			return 16
		}
		return 8

	case strings.HasPrefix(s, "iso.repodata"):
		if strings.HasSuffix(s, ".done") || strings.HasSuffix(s, ".skip") {
			return 28
		}
		return 20

	case strings.HasPrefix(s, "iso.packages"):
		if strings.HasSuffix(s, ".done") {
			return 34
		}
		if strings.HasSuffix(s, ".skip") {
			return 30
		}
		return 26

	case strings.HasPrefix(s, "iso.osv.query"):
		if strings.HasSuffix(s, ".done") {
			return 45
		}
		return 36

	case strings.HasPrefix(s, "iso.enrich.osv"):
		if strings.HasSuffix(s, ".done") || strings.HasSuffix(s, ".skip") {
			return 72
		}
		return 48

	case strings.HasPrefix(s, "iso.enrich.nvd"):
		if strings.HasSuffix(s, ".skip") {
			return 95
		}
		if strings.HasSuffix(s, ".done") {
			return 95
		}
		return 74

	case strings.HasPrefix(s, "iso.enrich.redhat"):
		if strings.HasSuffix(s, ".done") || strings.HasSuffix(s, ".skip") {
			return 97
		}
		return 93

	case strings.HasPrefix(s, "container.extract"), strings.HasPrefix(s, "container.layers"):
		if strings.HasSuffix(s, ".done") {
			return 18
		}
		return 8

	case strings.HasPrefix(s, "container.packages"):
		if strings.HasSuffix(s, ".done") {
			return 30
		}
		return 22

	case strings.HasPrefix(s, "container.osv.query"):
		if strings.HasSuffix(s, ".done") {
			return 45
		}
		return 34

	case strings.HasPrefix(s, "container.enrich.osv"):
		if strings.HasSuffix(s, ".done") || strings.HasSuffix(s, ".skip") {
			return 72
		}
		return 48

	case strings.HasPrefix(s, "osv."):
		return pctFromDetail(detail, 48, 72)

	case strings.HasPrefix(s, "container.enrich.nvd"):
		if strings.HasSuffix(s, ".skip") {
			return 95
		}
		if strings.HasSuffix(s, ".done") {
			return 95
		}
		return 74

	case strings.HasPrefix(s, "nvd."):
		return pctFromDetail(detail, 74, 95)

	case strings.HasPrefix(s, "binary."):
		if strings.HasSuffix(s, ".done") {
			return 95
		}
		if ratioRe.MatchString(detail) {
			return pctFromDetail(detail, 60, 95)
		}
		return 60
	}

	if strings.HasSuffix(s, ".done") || strings.HasSuffix(s, ".ok") {
		return 90
	}
	if isErr {
		return 90
	}
	if strings.HasSuffix(s, ".start") {
		return 10
	}
	return 50
}

func isErrorStage(stage string) bool {
	s := strings.ToLower(strings.TrimSpace(stage))
	return strings.HasSuffix(s, ".err") || strings.HasSuffix(s, ".error")
}

func isTerminalScanStage(stage string) bool {
	s := strings.ToLower(strings.TrimSpace(stage))
	return s == "scan.done" || s == "scan.summary" || s == "scan.err" || s == "scan.error"
}

func noisyStageGroup(stage string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(stage))
	switch {
	case strings.HasPrefix(s, "osv.fetch."):
		return "osv.fetch", true
	case strings.HasPrefix(s, "osv.cache."):
		return "osv.cache", true
	case strings.HasPrefix(s, "osv.upgrade.cve"):
		return "osv.upgrade.cve", true
	case strings.HasPrefix(s, "osv.debian.map."):
		return "osv.debian.map", true
	case strings.HasPrefix(s, "osv.advisory.drop"):
		return "osv.advisory.drop", true
	case strings.HasPrefix(s, "osv.query.chunk."):
		return "osv.query.chunk", true
	case strings.HasPrefix(s, "nvd.fetch."):
		return "nvd.fetch", true
	case strings.HasPrefix(s, "nvd.cache."):
		return "nvd.cache", true
	case strings.HasPrefix(s, "redhat.fetch."):
		return "redhat.fetch", true
	case strings.HasPrefix(s, "redhat.cache."):
		return "redhat.cache", true
	default:
		return "", false
	}
}

func shouldPersistEvent(stage string, pct int, ts time.Time, lastAt map[string]time.Time, lastPct map[string]int) bool {
	if isErrorStage(stage) || isTerminalScanStage(stage) {
		return true
	}
	group, noisy := noisyStageGroup(stage)
	if !noisy {
		return true
	}
	prevTS, hasTS := lastAt[group]
	prevPct, hasPct := lastPct[group]
	if !hasTS || !hasPct || pct > prevPct || ts.Sub(prevTS) >= noisyEventMinInterval {
		lastAt[group] = ts
		lastPct[group] = pct
		return true
	}
	return false
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
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if f == nil {
			log.Printf("job %s: progress file not found, continuing without tail", jobID)
			return
		}
		defer f.Close()

		r := bufio.NewReader(f)
		lastPct := 0
		lastProgressWriteAt := time.Time{}
		lastProgressWritePct := 0
		lastEventAtByGroup := make(map[string]time.Time)
		lastEventPctByGroup := make(map[string]int)
		for ctx.Err() == nil {
			line, err := r.ReadBytes('\n')
			if len(line) > 0 {
				var evt model.ProgressEvent
				if json.Unmarshal(line, &evt) == nil {
					p := derivePct(evt.Stage, evt.Detail)
					if p < lastPct {
						p = lastPct
					} else {
						lastPct = p
					}
					// write event with scanner-provided timestamp if present
					eventTS := time.Now()
					if t, err := time.Parse(time.RFC3339Nano, evt.TS); err == nil {
						eventTS = t
					}

					now := time.Now()
					if p > lastProgressWritePct || now.Sub(lastProgressWriteAt) >= progressUpdateMinInterval || isErrorStage(evt.Stage) || isTerminalScanStage(evt.Stage) {
						_ = st.UpdateProgress(ctx, jobID, p, evt.Stage+": "+evt.Detail)
						lastProgressWritePct = p
						lastProgressWriteAt = now
					}

					if shouldPersistEvent(evt.Stage, p, eventTS, lastEventAtByGroup, lastEventPctByGroup) {
						pctPtr := new(int)
						*pctPtr = p
						_ = st.InsertEvent(ctx, jobID, eventTS, evt.Stage, evt.Detail, pctPtr)
					}
					if strings.Contains(evt.Stage, "scan.done") {
						break
					}
				}
			}
			if err != nil {
				time.Sleep(300 * time.Millisecond)
			}
		}
	}()
	return func() {
		// Wait for the goroutine to finish, with a 30-second timeout to prevent
		// a hung DB call from leaking goroutines indefinitely.
		deadline := time.Now().Add(30 * time.Second)
		for !stopped.Load() {
			if time.Now().After(deadline) {
				log.Printf("job %s: TailProgress stop timed out after 30s", jobID)
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}
