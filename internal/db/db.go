package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yourorg/scanner-worker/internal/model"
)

const batchSize = 100

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
	OrgID        *string
	SettingsJSON []byte
	ProgressPct  int
	ProgressMsg  *string
	ReportBucket *string
	ReportKey    *string
	ErrorMsg     *string
	WorkerID     *string
}

type BackfillJob struct {
	ID           string
	ReportBucket string
	ReportKey    string
	ObjectKey    string
}

func (s *Store) notifyJobChanged(ctx context.Context, id string) {
	_, _ = s.Pool.Exec(ctx, `SELECT pg_notify('job_events', $1)`, id)
}

func (s *Store) InsertEvent(ctx context.Context, jobID string, ts time.Time, stage, detail string, pct *int) error {
	_, err := s.Pool.Exec(ctx, `
        INSERT INTO scan_events (job_id, ts, stage, detail, pct)
        VALUES ($1, $2, $3, $4, $5)
    `, jobID, ts, stage, detail, pct)
	return err
}

func (s *Store) AcquireNextQueued(ctx context.Context, workerID string) (*Job, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `
		SELECT id, bucket, object_key, mode, format, refs, org_id::text, settings_snapshot
		FROM scan_jobs
		WHERE status='queued'
		ORDER BY created_at
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`)
	var j Job
	if err := row.Scan(&j.ID, &j.Bucket, &j.ObjectKey, &j.Mode, &j.Format, &j.Refs, &j.OrgID, &j.SettingsJSON); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pgx.ErrNoRows
		}
		return nil, err
	}
	_, err = tx.Exec(ctx, `
		UPDATE scan_jobs
		SET status='running', started_at=now(), progress_pct=0, progress_msg='starting',
		    worker_id=$2
		WHERE id=$1
	`, j.ID, workerID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	j.Status = "running"
	j.WorkerID = &workerID
	s.notifyJobChanged(ctx, j.ID)
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
	if err == nil {
		s.notifyJobChanged(ctx, id)
	}
	return err
}

func (s *Store) MarkDone(
	ctx context.Context,
	id string,
	reportBucket, reportKey string,
	summaryJSON []byte,
	scanStatus *string,
	inventoryStatus *string,
	inventoryReason *string,
) error {
	// Cast to jsonb to ensure proper type instead of bytea
	_, err := s.Pool.Exec(ctx, `
		UPDATE scan_jobs
		SET status='done', finished_at=now(),
		    progress_pct=100, progress_msg='completed',
            report_bucket=$2, report_key=$3, summary_json=$4::jsonb,
			scan_status=$5, inventory_status=$6, inventory_reason=$7
		WHERE id=$1
    `, id, reportBucket, reportKey, string(summaryJSON), scanStatus, inventoryStatus, inventoryReason)
	if err == nil {
		s.notifyJobChanged(ctx, id)
	}
	return err
}

// ReplaceJobArtifacts deletes old artifacts and batch-inserts findings, files,
// and packages from the given report. Inserts are grouped into multi-value
// batches of up to 100 rows for dramatically better throughput on large reports.
func (s *Store) ReplaceJobArtifacts(ctx context.Context, jobID string, report *model.ScanReport) error {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM scan_findings WHERE job_id=$1::uuid`, jobID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM scan_files WHERE job_id=$1::uuid`, jobID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM scan_packages WHERE job_id=$1::uuid`, jobID); err != nil {
		return err
	}

	// ---- Batch insert findings ----
	if err := batchInsertFindings(ctx, tx, jobID, report.Findings); err != nil {
		return fmt.Errorf("batch insert findings: %w", err)
	}

	// ---- Batch insert files ----
	seenPaths := map[string]struct{}{}
	dedupFiles := make([]model.FileRow, 0, len(report.Files))
	for _, file := range report.Files {
		if file.Path == "" {
			continue
		}
		if _, exists := seenPaths[file.Path]; exists {
			continue
		}
		seenPaths[file.Path] = struct{}{}
		dedupFiles = append(dedupFiles, file)
	}
	if err := batchInsertFiles(ctx, tx, jobID, dedupFiles); err != nil {
		return fmt.Errorf("batch insert files: %w", err)
	}

	// ---- Batch insert packages ----
	pkgs := collectPackages(report)
	if err := batchInsertPackages(ctx, tx, jobID, pkgs); err != nil {
		return fmt.Errorf("batch insert packages: %w", err)
	}

	return tx.Commit(ctx)
}

// batchInsertFindings inserts findings in groups of batchSize using multi-value
// INSERT statements. Each finding also gets its references inserted.
func batchInsertFindings(ctx context.Context, tx pgx.Tx, jobID string, findings []model.Finding) error {
	// We need RETURNING id for refs, so we use pgx.Batch to pipeline individual
	// inserts while still avoiding per-row round trips.
	for start := 0; start < len(findings); start += batchSize {
		end := start + batchSize
		if end > len(findings) {
			end = len(findings)
		}
		chunk := findings[start:end]

		batch := &pgx.Batch{}
		for _, f := range chunk {
			sourceIDs := f.SourceIDs
			if sourceIDs == nil {
				sourceIDs = []string{}
			}
			sourceIDsJSON, _ := json.Marshal(sourceIDs)
			rawJSON, _ := json.Marshal(f)

			var (
				pkgName      *string
				pkgEcosystem *string
				pkgVersion   *string
				cvssBase     *float64
				cvssVector   *string
			)
			if f.Package != nil {
				pkgName = &f.Package.Name
				pkgEcosystem = &f.Package.Ecosystem
				pkgVersion = &f.Package.Version
			}
			if f.CVSS != nil {
				base := f.CVSS.Base
				cvssBase = &base
				cvssVector = &f.CVSS.Vector
			}

			batch.Queue(`
INSERT INTO scan_findings (
  job_id, finding_id, package_name, package_ecosystem, package_version,
  severity, cvss_base, cvss_vector, confidence_tier, evidence_source,
  accuracy_note, fixed, fixed_in, recommendation, description,
  source_ids, raw
)
VALUES (
  $1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
  $16::jsonb, $17::jsonb
)
ON CONFLICT (job_id, finding_id, package_name, package_version, confidence_tier)
DO UPDATE SET
  severity = EXCLUDED.severity,
  cvss_base = EXCLUDED.cvss_base,
  cvss_vector = EXCLUDED.cvss_vector,
  evidence_source = EXCLUDED.evidence_source,
  accuracy_note = EXCLUDED.accuracy_note,
  fixed = EXCLUDED.fixed,
  fixed_in = EXCLUDED.fixed_in,
  recommendation = EXCLUDED.recommendation,
  description = EXCLUDED.description,
  source_ids = EXCLUDED.source_ids,
  raw = EXCLUDED.raw
RETURNING id`,
				jobID,
				f.ID,
				pkgName,
				pkgEcosystem,
				pkgVersion,
				nullableString(f.Severity),
				cvssBase,
				cvssVector,
				coalesceString(f.ConfidenceTier, "confirmed_installed"),
				coalesceString(f.EvidenceSource, "installed_db"),
				nullableString(f.AccuracyNote),
				f.Fixed,
				nullableString(f.FixedIn),
				nullableString(f.Recommendation),
				nullableString(f.Description),
				string(sourceIDsJSON),
				string(rawJSON),
			)
		}

		br := tx.SendBatch(ctx, batch)
		findingRowIDs := make([]int64, 0, len(chunk))
		for range chunk {
			var id int64
			if err := br.QueryRow().Scan(&id); err != nil {
				_ = br.Close()
				return err
			}
			findingRowIDs = append(findingRowIDs, id)
		}
		if err := br.Close(); err != nil {
			return err
		}

		// Now batch-insert refs for this chunk of findings
		if err := batchInsertRefs(ctx, tx, chunk, findingRowIDs); err != nil {
			return err
		}
	}
	return nil
}

// batchInsertRefs inserts finding references using pgx.Batch for the given
// chunk of findings and their corresponding row IDs.
func batchInsertRefs(ctx context.Context, tx pgx.Tx, findings []model.Finding, rowIDs []int64) error {
	batch := &pgx.Batch{}
	count := 0
	for i, f := range findings {
		for _, ref := range f.References {
			if ref.URL == "" {
				continue
			}
			batch.Queue(`
INSERT INTO scan_finding_refs (finding_row_id, ref_type, url)
VALUES ($1, $2, $3)
ON CONFLICT (finding_row_id, ref_type, url) DO NOTHING`,
				rowIDs[i], coalesceString(ref.Type, "ref"), ref.URL)
			count++
		}
	}
	if count == 0 {
		return nil
	}
	br := tx.SendBatch(ctx, batch)
	for i := 0; i < count; i++ {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return err
		}
	}
	return br.Close()
}

// batchInsertFiles inserts file rows in groups of batchSize using multi-value
// INSERT statements for bulk throughput.
func batchInsertFiles(ctx context.Context, tx pgx.Tx, jobID string, files []model.FileRow) error {
	for start := 0; start < len(files); start += batchSize {
		end := start + batchSize
		if end > len(files) {
			end = len(files)
		}
		chunk := files[start:end]

		// Build a multi-value INSERT: INSERT INTO ... VALUES ($1,...), ($9,...), ...
		const colCount = 8
		var sb strings.Builder
		sb.WriteString(`
INSERT INTO scan_files (
  job_id, path, entry_type, size_bytes, mode, mtime, sha256, parent_path
) VALUES `)
		args := make([]interface{}, 0, len(chunk)*colCount)
		for i, file := range chunk {
			if i > 0 {
				sb.WriteString(", ")
			}
			base := i*colCount + 1
			sb.WriteString(fmt.Sprintf(
				"($%d::uuid, $%d, $%d, $%d, $%d, $%d::timestamptz, $%d, $%d)",
				base, base+1, base+2, base+3, base+4, base+5, base+6, base+7,
			))
			args = append(args,
				jobID,
				file.Path,
				coalesceString(file.EntryType, "file"),
				file.SizeBytes,
				nullableString(file.Mode),
				nullableString(file.MTime),
				nullableString(file.SHA256),
				nullableString(file.ParentPath),
			)
		}
		sb.WriteString(`
ON CONFLICT (job_id, path) DO UPDATE SET
  entry_type = EXCLUDED.entry_type,
  size_bytes = EXCLUDED.size_bytes,
  mode = EXCLUDED.mode,
  mtime = EXCLUDED.mtime,
  sha256 = EXCLUDED.sha256,
  parent_path = EXCLUDED.parent_path`)

		if _, err := tx.Exec(ctx, sb.String(), args...); err != nil {
			return err
		}
	}
	return nil
}

// batchInsertPackages inserts package rows in groups of batchSize using
// multi-value INSERT statements.
func batchInsertPackages(ctx context.Context, tx pgx.Tx, jobID string, pkgs []model.PackageRow) error {
	for start := 0; start < len(pkgs); start += batchSize {
		end := start + batchSize
		if end > len(pkgs) {
			end = len(pkgs)
		}
		chunk := pkgs[start:end]

		const colCount = 9
		var sb strings.Builder
		sb.WriteString(`
INSERT INTO scan_packages (
  job_id, name, ecosystem, version, source_kind, source_path,
  confidence_tier, evidence_source, raw
) VALUES `)
		args := make([]interface{}, 0, len(chunk)*colCount)
		for i, pkg := range chunk {
			if i > 0 {
				sb.WriteString(", ")
			}
			rawJSON, _ := json.Marshal(pkg)
			base := i*colCount + 1
			sb.WriteString(fmt.Sprintf(
				"($%d::uuid, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d::jsonb)",
				base, base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8,
			))
			args = append(args,
				jobID,
				pkg.Name,
				coalesceString(pkg.Ecosystem, "unknown"),
				pkg.Version,
				coalesceString(pkg.SourceKind, "scanner_inventory"),
				coalesceString(pkg.SourcePath, ""),
				coalesceString(pkg.ConfidenceTier, "confirmed_installed"),
				coalesceString(pkg.EvidenceSource, "installed_db"),
				string(rawJSON),
			)
		}
		sb.WriteString(`
ON CONFLICT (job_id, name, ecosystem, version, source_kind, source_path)
DO UPDATE SET
  confidence_tier = EXCLUDED.confidence_tier,
  evidence_source = EXCLUDED.evidence_source,
  raw = EXCLUDED.raw`)

		if _, err := tx.Exec(ctx, sb.String(), args...); err != nil {
			return err
		}
	}
	return nil
}

func collectPackages(report *model.ScanReport) []model.PackageRow {
	seen := map[string]struct{}{}
	out := make([]model.PackageRow, 0)

	add := func(row model.PackageRow) {
		name := strings.TrimSpace(row.Name)
		version := strings.TrimSpace(row.Version)
		if name == "" || version == "" {
			return
		}

		row.Name = name
		row.Version = version
		row.Ecosystem = strings.TrimSpace(row.Ecosystem)
		row.SourceKind = strings.TrimSpace(row.SourceKind)
		row.SourcePath = strings.TrimSpace(row.SourcePath)
		row.ConfidenceTier = strings.TrimSpace(row.ConfidenceTier)
		row.EvidenceSource = strings.TrimSpace(row.EvidenceSource)

		key := strings.Join([]string{
			strings.ToLower(row.Name),
			strings.ToLower(coalesceString(row.Ecosystem, "unknown")),
			row.Version,
			strings.ToLower(coalesceString(row.SourceKind, "scanner_inventory")),
			row.SourcePath,
		}, "|")
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		out = append(out, row)
	}

	for _, row := range report.Packages {
		add(row)
	}

	if len(out) > 0 {
		return out
	}

	for _, finding := range report.Findings {
		if finding.Package == nil {
			continue
		}
		add(model.PackageRow{
			Name:           finding.Package.Name,
			Ecosystem:      finding.Package.Ecosystem,
			Version:        finding.Package.Version,
			SourceKind:     "derived_from_findings",
			SourcePath:     "",
			ConfidenceTier: coalesceString(finding.ConfidenceTier, "confirmed_installed"),
			EvidenceSource: coalesceString(finding.EvidenceSource, "installed_db"),
		})
	}

	return out
}

func coalesceString(v string, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func nullableString(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func (s *Store) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.Pool.Ping(ctx)
}

func (s *Store) EnsureSchema(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS scan_jobs (
  id UUID PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('queued','running','done','failed','deleting')),
  bucket TEXT NOT NULL,
  object_key TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'light',
  format TEXT NOT NULL DEFAULT 'json',
  refs BOOLEAN NOT NULL DEFAULT FALSE,
  org_id UUID,
  created_by_user_id UUID,
  created_by_api_key_id UUID,
  settings_snapshot JSONB,
  scan_status TEXT,
  inventory_status TEXT,
  inventory_reason TEXT,
  worker_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  progress_pct INTEGER NOT NULL DEFAULT 0 CHECK (progress_pct BETWEEN 0 AND 100),
  progress_msg TEXT,
  report_bucket TEXT,
  report_key TEXT,
  error_msg TEXT,
  summary_json JSONB
);

ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS created_by_user_id UUID;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS created_by_api_key_id UUID;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS settings_snapshot JSONB;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS scan_status TEXT;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS inventory_status TEXT;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS inventory_reason TEXT;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS worker_id TEXT;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'scan_jobs_status_check') THEN
    ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_status_check;
  END IF;
  ALTER TABLE scan_jobs
    ADD CONSTRAINT scan_jobs_status_check CHECK (status IN ('queued','running','done','failed','deleting'));
EXCEPTION
  WHEN duplicate_object THEN NULL;
END$$;

CREATE INDEX IF NOT EXISTS idx_scan_jobs_status_created ON scan_jobs (status, created_at);

CREATE TABLE IF NOT EXISTS scan_events (
  id BIGSERIAL PRIMARY KEY,
  job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  stage TEXT NOT NULL,
  detail TEXT NOT NULL,
  pct SMALLINT
);

CREATE INDEX IF NOT EXISTS idx_scan_events_job_ts ON scan_events (job_id, ts);
CREATE INDEX IF NOT EXISTS idx_scan_events_job_id_id ON scan_events (job_id, id);

CREATE OR REPLACE FUNCTION notify_job_event() RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('job_events', NEW.id::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'scan_jobs_notify') THEN
    CREATE TRIGGER scan_jobs_notify
    AFTER INSERT OR UPDATE ON scan_jobs
    FOR EACH ROW EXECUTE FUNCTION notify_job_event();
  END IF;
END$$;

CREATE TABLE IF NOT EXISTS scan_findings (
  id BIGSERIAL PRIMARY KEY,
  job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL,
  package_name TEXT,
  package_ecosystem TEXT,
  package_version TEXT,
  severity TEXT,
  cvss_base DOUBLE PRECISION,
  cvss_vector TEXT,
  confidence_tier TEXT NOT NULL DEFAULT 'confirmed_installed',
  evidence_source TEXT NOT NULL DEFAULT 'installed_db',
  accuracy_note TEXT,
  fixed BOOLEAN,
  fixed_in TEXT,
  recommendation TEXT,
  description TEXT,
  source_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  raw JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(job_id, finding_id, package_name, package_version, confidence_tier)
);

CREATE TABLE IF NOT EXISTS scan_finding_refs (
  id BIGSERIAL PRIMARY KEY,
  finding_row_id BIGINT NOT NULL REFERENCES scan_findings(id) ON DELETE CASCADE,
  ref_type TEXT NOT NULL,
  url TEXT NOT NULL,
  UNIQUE(finding_row_id, ref_type, url)
);

CREATE TABLE IF NOT EXISTS scan_files (
  id BIGSERIAL PRIMARY KEY,
  job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  path TEXT NOT NULL,
  entry_type TEXT NOT NULL,
  size_bytes BIGINT,
  mode TEXT,
  mtime TIMESTAMPTZ,
  sha256 TEXT,
  parent_path TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(job_id, path)
);

CREATE TABLE IF NOT EXISTS scan_packages (
  id BIGSERIAL PRIMARY KEY,
  job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  version TEXT NOT NULL,
  source_kind TEXT NOT NULL,
  source_path TEXT,
  confidence_tier TEXT NOT NULL DEFAULT 'confirmed_installed',
  evidence_source TEXT NOT NULL DEFAULT 'installed_db',
  raw JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(job_id, name, ecosystem, version, source_kind, source_path)
);

CREATE INDEX IF NOT EXISTS idx_scan_findings_job_sev_id ON scan_findings(job_id, severity, finding_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_job_tier ON scan_findings(job_id, confidence_tier);
CREATE INDEX IF NOT EXISTS idx_scan_finding_refs_finding ON scan_finding_refs(finding_row_id);
CREATE INDEX IF NOT EXISTS idx_scan_files_job_parent_path ON scan_files(job_id, parent_path, path);
CREATE INDEX IF NOT EXISTS idx_scan_files_job_path ON scan_files(job_id, path);
CREATE INDEX IF NOT EXISTS idx_scan_packages_job_name_version ON scan_packages(job_id, name, version);
CREATE INDEX IF NOT EXISTS idx_scan_packages_job_source_path ON scan_packages(job_id, source_path);
`)
	return err
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
		s.notifyJobChanged(ctx, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}

// RequeueStaleRunning finds jobs stuck in 'running' with no recent heartbeat
// and re-queues them by setting status back to 'queued'. Used at startup for
// graceful recovery of jobs orphaned by crashed workers.
func (s *Store) RequeueStaleRunning(ctx context.Context, idleFor time.Duration) ([]string, error) {
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
			  AND COALESCE(ev.last_event_ts, j.started_at, j.created_at)
			      < now() - ($1::bigint * interval '1 second')
		)
		UPDATE scan_jobs j
		SET status='queued',
		    started_at=NULL,
		    worker_id=NULL,
		    progress_pct=0,
		    progress_msg='re-queued: previous worker lost'
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
		s.notifyJobChanged(ctx, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}

func (s *Store) ListBackfillCandidates(ctx context.Context, limit int) ([]BackfillJob, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `
SELECT j.id::text, j.report_bucket, j.report_key, j.object_key
FROM scan_jobs j
WHERE j.status='done'
  AND j.report_bucket IS NOT NULL
  AND j.report_key IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM scan_files sf WHERE sf.job_id=j.id)
ORDER BY COALESCE(j.finished_at, j.created_at), j.id
LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]BackfillJob, 0, limit)
	for rows.Next() {
		var j BackfillJob
		if err := rows.Scan(&j.ID, &j.ReportBucket, &j.ReportKey, &j.ObjectKey); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
