ALTER TABLE backup_runs
ADD COLUMN size_bytes INTEGER
CHECK (size_bytes IS NULL OR size_bytes >= 0);

ALTER TABLE backup_runs
ADD COLUMN error_code TEXT
CHECK (
    error_code IS NULL
    OR (
        length(error_code) BETWEEN 1 AND 64
        AND error_code NOT GLOB '*[^A-Z0-9_]*'
    )
);

ALTER TABLE backup_runs
ADD COLUMN retained INTEGER NOT NULL DEFAULT 1
CHECK (retained IN (0, 1));

ALTER TABLE backup_runs
ADD COLUMN deleted_at TEXT;

UPDATE backup_runs
SET
    status = 'failed',
    destination = NULL,
    checksum = NULL,
    size_bytes = NULL,
    completed_at = COALESCE(completed_at, started_at),
    error_message = 'legacy backup record cannot be verified',
    error_code = 'LEGACY_RECORD',
    retained = 0
WHERE destination IS NOT NULL OR status = 'running';
