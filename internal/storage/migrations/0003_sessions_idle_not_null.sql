ALTER TABLE sessions RENAME TO sessions_legacy;

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    idle_expires_at TEXT NOT NULL,
    recent_totp_at TEXT
);

INSERT INTO sessions (
    id,
    user_id,
    token_hash,
    created_at,
    expires_at,
    revoked_at,
    idle_expires_at,
    recent_totp_at
)
SELECT
    id,
    user_id,
    token_hash,
    created_at,
    expires_at,
    revoked_at,
    COALESCE(idle_expires_at, '1970-01-01T00:00:00Z'),
    recent_totp_at
FROM sessions_legacy;

DROP TABLE sessions_legacy;

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
