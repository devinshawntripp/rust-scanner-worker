CREATE TABLE IF NOT EXISTS scan_jobs (
  id              UUID PRIMARY KEY,
  status          TEXT NOT NULL CHECK (status IN ('queued','running','done','failed')),
  bucket          TEXT NOT NULL,
  object_key      TEXT NOT NULL,
  mode            TEXT NOT NULL DEFAULT 'light',      -- 'light' | 'deep'
  format          TEXT NOT NULL DEFAULT 'json',       -- 'json'  | 'text'
  refs            BOOLEAN NOT NULL DEFAULT FALSE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at      TIMESTAMPTZ,
  finished_at     TIMESTAMPTZ,
  progress_pct    INTEGER NOT NULL DEFAULT 0 CHECK (progress_pct BETWEEN 0 AND 100),
  progress_msg    TEXT,
  report_bucket   TEXT,
  report_key      TEXT,
  error_msg       TEXT,
  summary_json    JSONB    -- store severity totals, etc.
);

-- helpful index for worker polling:
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status_created ON scan_jobs (status, created_at);

-- event log for per-job progress history
CREATE TABLE IF NOT EXISTS scan_events (
  id       BIGSERIAL PRIMARY KEY,
  job_id   UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  ts       TIMESTAMPTZ NOT NULL DEFAULT now(),
  stage    TEXT NOT NULL,
  detail   TEXT NOT NULL,
  pct      SMALLINT
);

CREATE INDEX IF NOT EXISTS idx_scan_events_job_ts ON scan_events (job_id, ts);
