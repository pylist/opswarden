CREATE TABLE health_probe (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    marker INTEGER NOT NULL DEFAULT 0
);

INSERT INTO health_probe (id, marker) VALUES (1, 0);

ALTER TABLE backup_runs
ADD COLUMN verification_status TEXT NOT NULL DEFAULT 'unknown'
CHECK (verification_status IN ('unknown', 'passed', 'failed', 'retired'));

ALTER TABLE backup_runs ADD COLUMN verified_at TEXT;
ALTER TABLE backup_runs
ADD COLUMN verification_error_code TEXT
CHECK (
    verification_error_code IS NULL
    OR (
        length(verification_error_code) BETWEEN 1 AND 64
        AND verification_error_code NOT GLOB '*[^A-Z0-9_]*'
    )
);
