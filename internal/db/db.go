package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, url string) (*Store, error) {
	p, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	return &Store{Pool: p}, nil
}

type Job struct {
	ID           string
	Status       string
	Bucket       string
	ObjectKey    string
	Mode         string
	Format       string
	Refs         bool
	ProgressPct  int
	ProgressMsg  *string
	ReportBucket *string
	ReportKey    *string
	ErrorMsg     *string
}

func (s *Store) InsertEvent(ctx context.Context, jobID string, ts time.Time, stage, detail string, pct *int) error {
	_, err := s.Pool.Exec(ctx, `
        INSERT INTO scan_events (job_id, ts, stage, detail, pct)
        VALUES ($1, $2, $3, $4, $5)
    `, jobID, ts, stage, detail, pct)
	return err
}

func (s *Store) AcquireNextQueued(ctx context.Context) (*Job, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `
		SELECT id, bucket, object_key, mode, format, refs
		FROM scan_jobs
		WHERE status='queued'
		ORDER BY created_at
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`)
	var j Job
	if err := row.Scan(&j.ID, &j.Bucket, &j.ObjectKey, &j.Mode, &j.Format, &j.Refs); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pgx.ErrNoRows
		}
		return nil, err
	}
	_, err = tx.Exec(ctx, `
		UPDATE scan_jobs
		SET status='running', started_at=now(), progress_pct=0, progress_msg='starting'
		WHERE id=$1
	`, j.ID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	j.Status = "running"
	return &j, nil
}

func (s *Store) UpdateProgress(ctx context.Context, id string, pct int, msg string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE scan_jobs
		SET progress_pct=GREATEST(progress_pct, $2),
		    progress_msg=CASE WHEN $2 >= progress_pct THEN $3 ELSE progress_msg END
		WHERE id=$1
		  AND status='running'
	`, id, pct, msg)
	return err
}

func (s *Store) MarkFailed(ctx context.Context, id, errMsg string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE scan_jobs
		SET status='failed',
		    finished_at=now(),
		    error_msg=$2,
		    progress_msg=COALESCE(progress_msg, $2)
		WHERE id=$1
		  AND status IN ('queued','running')
	`, id, errMsg)
	return err
}

func (s *Store) MarkDone(ctx context.Context, id string, reportBucket, reportKey string, summaryJSON []byte) error {
	// Cast to jsonb to ensure proper type instead of bytea
	_, err := s.Pool.Exec(ctx, `
		UPDATE scan_jobs
		SET status='done', finished_at=now(),
		    progress_pct=100, progress_msg='completed',
            report_bucket=$2, report_key=$3, summary_json=$4::jsonb
		WHERE id=$1
    `, id, reportBucket, reportKey, string(summaryJSON))
	return err
}

func (s *Store) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.Pool.Ping(ctx)
}

func (s *Store) FailStaleRunning(ctx context.Context, idleFor time.Duration) ([]string, error) {
	seconds := int64(idleFor.Seconds())
	if seconds <= 0 {
		return nil, nil
	}
	rows, err := s.Pool.Query(ctx, `
		WITH stale AS (
			SELECT j.id
			FROM scan_jobs j
			LEFT JOIN LATERAL (
				SELECT MAX(ts) AS last_event_ts
				FROM scan_events e
				WHERE e.job_id = j.id
			) ev ON true
			WHERE j.status='running'
			  AND COALESCE(ev.last_event_ts, j.started_at, j.created_at) < now() - (
				CASE
					WHEN j.progress_pct >= 95 THEN ($1::bigint * 4)
					ELSE $1::bigint
				END * interval '1 second'
			  )
		)
		UPDATE scan_jobs j
		SET status='failed',
		    finished_at=now(),
		    error_msg='worker timeout: no progress heartbeat',
		    progress_msg='worker timeout: no progress heartbeat'
		FROM stale
		WHERE j.id = stale.id
		RETURNING j.id::text
	`, seconds)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}
