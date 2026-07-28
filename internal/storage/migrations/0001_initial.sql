CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    normalized_email TEXT NOT NULL UNIQUE,
    password_hash BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TEXT
);

CREATE TABLE user_totp (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    encrypted_secret BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE recovery_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at TEXT,
    UNIQUE (user_id, code_hash)
);

CREATE INDEX idx_recovery_codes_user ON recovery_codes(user_id);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE TABLE spaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TEXT
);

CREATE TABLE space_memberships (
    space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (space_id, user_id)
);

CREATE INDEX idx_space_memberships_user ON space_memberships(user_id, space_id);

CREATE TABLE agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TEXT
);

CREATE TABLE agent_tokens (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT,
    revoked_at TEXT
);

CREATE INDEX idx_agent_tokens_agent ON agent_tokens(agent_id);
CREATE INDEX idx_agent_tokens_expires ON agent_tokens(expires_at);

CREATE TABLE agent_space_grants (
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (agent_id, space_id)
);

CREATE INDEX idx_agent_space_grants_space ON agent_space_grants(space_id, agent_id);

CREATE TABLE assets (
    id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TEXT,
    UNIQUE (id, space_id)
);

CREATE INDEX idx_assets_space_type ON assets(space_id, type);
CREATE INDEX idx_assets_space_deleted ON assets(space_id, deleted_at);

CREATE TABLE asset_tags (
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (asset_id, tag)
);

CREATE INDEX idx_asset_tags_tag ON asset_tags(tag, asset_id);

CREATE TABLE credentials (
    id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TEXT,
    UNIQUE (id, space_id)
);

CREATE INDEX idx_credentials_space_type ON credentials(space_id, type);
CREATE INDEX idx_credentials_space_deleted ON credentials(space_id, deleted_at);

CREATE TABLE credential_versions (
    id TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    version INTEGER NOT NULL CHECK (version > 0),
    encrypted_payload BLOB NOT NULL,
    created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (credential_id, version)
);

CREATE INDEX idx_credential_versions_credential ON credential_versions(credential_id, version DESC);

CREATE TRIGGER credential_versions_identity_immutable
BEFORE UPDATE OF credential_id, version ON credential_versions
BEGIN
    SELECT RAISE(ABORT, 'credential version identity is immutable');
END;

CREATE TABLE credential_tags (
    credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (credential_id, tag)
);

CREATE INDEX idx_credential_tags_tag ON credential_tags(tag, credential_id);

CREATE TABLE asset_credentials (
    space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (asset_id, credential_id),
    FOREIGN KEY (asset_id, space_id) REFERENCES assets(id, space_id) ON DELETE CASCADE,
    FOREIGN KEY (credential_id, space_id) REFERENCES credentials(id, space_id) ON DELETE CASCADE
);

CREATE INDEX idx_asset_credentials_space ON asset_credentials(space_id);
CREATE INDEX idx_asset_credentials_credential ON asset_credentials(credential_id, asset_id);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    space_id TEXT REFERENCES spaces(id) ON DELETE SET NULL,
    actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    actor_agent_id TEXT REFERENCES agents(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    metadata_json TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_events_space_created ON audit_events(space_id, created_at DESC);
CREATE INDEX idx_audit_events_entity ON audit_events(space_id, entity_type, entity_id);

CREATE TABLE idempotency_records (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    endpoint TEXT NOT NULL,
    key_hash BLOB NOT NULL,
    response_status INTEGER NOT NULL,
    response_headers BLOB,
    response_body BLOB,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    UNIQUE (agent_id, endpoint, key_hash)
);

CREATE INDEX idx_idempotency_records_expires ON idempotency_records(expires_at);

CREATE TABLE backup_runs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    destination TEXT,
    checksum TEXT,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT,
    error_message TEXT
);

CREATE INDEX idx_backup_runs_started ON backup_runs(started_at DESC);
