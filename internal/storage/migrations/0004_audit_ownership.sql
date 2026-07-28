ALTER TABLE audit_events RENAME TO audit_events_legacy;

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    space_id TEXT REFERENCES spaces(id) ON DELETE RESTRICT,
    actor_user_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
    actor_agent_id TEXT REFERENCES agents(id) ON DELETE RESTRICT,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    metadata_json TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO audit_events (
    id,
    space_id,
    actor_user_id,
    actor_agent_id,
    action,
    entity_type,
    entity_id,
    metadata_json,
    created_at
)
SELECT
    id,
    space_id,
    actor_user_id,
    actor_agent_id,
    action,
    entity_type,
    entity_id,
    CASE
        WHEN metadata_json IS NULL THEN NULL
        ELSE json_remove(metadata_json, '$.token_id')
    END,
    created_at
FROM audit_events_legacy;

DROP TABLE audit_events_legacy;

CREATE INDEX idx_audit_events_space_created
ON audit_events(space_id, created_at DESC);

CREATE INDEX idx_audit_events_entity
ON audit_events(space_id, entity_type, entity_id);
