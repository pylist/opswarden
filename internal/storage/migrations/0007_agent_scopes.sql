ALTER TABLE agent_tokens ADD COLUMN token_prefix TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_tokens ADD COLUMN last_used_at TEXT;

ALTER TABLE agent_space_grants ADD COLUMN scopes_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE agent_space_grants ADD COLUMN labels_json TEXT NOT NULL DEFAULT '{}';
