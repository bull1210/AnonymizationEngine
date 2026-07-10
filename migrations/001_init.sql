-- Postgres schema (production). SQLite equivalent is created automatically
-- by anonymizer.core.storage for dev/standalone runs.

CREATE TABLE IF NOT EXISTS transform_receipts (
    file_id                TEXT NOT NULL,
    job_id                 TEXT NOT NULL,
    mode                   TEXT NOT NULL,
    policy_version         TEXT NOT NULL,
    canonicalizer_version  TEXT NOT NULL,
    status                 TEXT NOT NULL,
    receipt_json           JSONB NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Idempotency key:
    PRIMARY KEY (file_id, job_id, policy_version, canonicalizer_version)
);
CREATE INDEX IF NOT EXISTS idx_receipts_status ON transform_receipts (status);

-- Truncation-collision registry: stores FULL digests only, never originals.
CREATE TABLE IF NOT EXISTS pseudonym_collisions (
    entity_class TEXT NOT NULL,
    prefix       TEXT NOT NULL,
    digest       TEXT NOT NULL,
    token_length INTEGER NOT NULL,
    PRIMARY KEY (entity_class, prefix)
);

-- Re-identification vault: rows exist ONLY for reversible=true RAG jobs.
CREATE TABLE IF NOT EXISTS reid_vault (
    pseudonym   TEXT PRIMARY KEY,
    ciphertext  BYTEA NOT NULL,          -- AES-256-GCM(nonce || ct), vault key
    entity_type TEXT NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
    ts     TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    detail JSONB NOT NULL
);
