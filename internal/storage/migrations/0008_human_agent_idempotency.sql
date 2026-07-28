CREATE TABLE human_agent_idempotency_records (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    endpoint TEXT NOT NULL,
    key_hash BLOB NOT NULL CHECK (length(key_hash) = 32),
    request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
    resource_id TEXT NOT NULL,
    resource_version INTEGER NOT NULL CHECK (resource_version > 0),
    response_status INTEGER NOT NULL CHECK (response_status BETWEEN 200 AND 299),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    UNIQUE (user_id, endpoint, key_hash)
);

CREATE INDEX idx_human_agent_idempotency_expires
ON human_agent_idempotency_records(expires_at);
