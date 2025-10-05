package db

import (
	"context"
	"errors"
    "strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type Store struct { Conn *pgx.Conn }

func Open(ctx context.Context, url string) (*Store, error) {
    c, err := pgx.Connect(ctx, url)
    if err != nil { return nil, err }
    return &Store{Conn: c}, nil
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

func (s *Store) AcquireNextQueued(ctx context.Context) (*Job, error) {
    tx, err := s.Conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil { return nil, err }
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
	if err != nil { return nil, err }
	if err := tx.Commit(ctx); err != nil { return nil, err }
	j.Status = "running"
	return &j, nil
}

func (s *Store) UpdateProgress(ctx context.Context, id string, pct int, msg string) error {
    _, err := s.Conn.Exec(ctx, `
		UPDATE scan_jobs
		SET progress_pct=$2, progress_msg=$3
		WHERE id=$1
	`, id, pct, msg)
    if err == nil { return nil }
    // If connection is closed, attempt a single reconnect and retry
    if isConnClosed(err) {
        if recErr := s.reconnect(ctx); recErr == nil {
            _, err = s.Conn.Exec(ctx, `
                UPDATE scan_jobs SET progress_pct=$2, progress_msg=$3 WHERE id=$1
            `, id, pct, msg)
        }
    }
    return err
}

func (s *Store) MarkFailed(ctx context.Context, id, errMsg string) error {
    _, err := s.Conn.Exec(ctx, `
		UPDATE scan_jobs
		SET status='failed', finished_at=now(), error_msg=$2
		WHERE id=$1
	`, id, errMsg)
    if err == nil { return nil }
    if isConnClosed(err) {
        if recErr := s.reconnect(ctx); recErr == nil {
            _, err = s.Conn.Exec(ctx, `
                UPDATE scan_jobs SET status='failed', finished_at=now(), error_msg=$2 WHERE id=$1
            `, id, errMsg)
        }
    }
    return err
}

func (s *Store) MarkDone(ctx context.Context, id string, reportBucket, reportKey string, summaryJSON []byte) error {
    // Cast to jsonb to ensure proper type instead of bytea
    _, err := s.Conn.Exec(ctx, `
		UPDATE scan_jobs
		SET status='done', finished_at=now(),
		    progress_pct=100, progress_msg='completed',
            report_bucket=$2, report_key=$3, summary_json=$4::jsonb
		WHERE id=$1
    `, id, reportBucket, reportKey, string(summaryJSON))
    if err == nil { return nil }
    if isConnClosed(err) {
        if recErr := s.reconnect(ctx); recErr == nil {
            _, err = s.Conn.Exec(ctx, `
                UPDATE scan_jobs SET status='done', finished_at=now(), progress_pct=100, progress_msg='completed', report_bucket=$2, report_key=$3, summary_json=$4::jsonb WHERE id=$1
            `, id, reportBucket, reportKey, string(summaryJSON))
        }
    }
    return err
}

func (s *Store) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
    return s.Conn.Ping(ctx)
}

func (s *Store) reconnect(ctx context.Context) error {
    // Use the same config to reconnect
    cfg := s.Conn.Config()
    // Close existing conn just in case
    _ = s.Conn.Close(ctx)
    c, err := pgx.ConnectConfig(ctx, cfg)
    if err != nil { return err }
    s.Conn = c
    return nil
}

func isConnClosed(err error) bool {
    if err == nil { return false }
    // pgx v5 does not export ErrClosed on Conn; match by message
    // observed error text: "conn closed"
    return strings.Contains(strings.ToLower(err.Error()), "conn closed")
}
