ALTER TABLE assets ADD COLUMN hostname TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN operating_system TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN environment TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN status TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN ips_json TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(ips_json) AND json_type(ips_json) = 'array');
ALTER TABLE assets ADD COLUMN ports_json TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(ports_json) AND json_type(ports_json) = 'array');
ALTER TABLE assets ADD COLUMN notes TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN version INTEGER NOT NULL DEFAULT 1
    CHECK (version > 0);

CREATE INDEX idx_assets_space_environment
ON assets(space_id, environment, id);

CREATE INDEX idx_assets_space_status
ON assets(space_id, status, id);
