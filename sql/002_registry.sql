-- Registry credential storage per org
CREATE TABLE IF NOT EXISTS registry_configs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL,
    name            TEXT NOT NULL,
    registry_url    TEXT NOT NULL,
    username        TEXT,
    token_encrypted BYTEA,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, name)
);
CREATE INDEX IF NOT EXISTS idx_registry_configs_org ON registry_configs(org_id);

-- Extend scan_jobs for registry sources
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS source_type TEXT NOT NULL DEFAULT 'upload';
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS registry_image TEXT;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS registry_config_id UUID;
