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

UPDATE assets
SET notes = CASE
    WHEN description IS NULL THEN ''
    WHEN typeof(description) != 'text' THEN ''
    WHEN length(CAST(description AS BLOB)) > 4096 THEN ''
    WHEN instr(description, char(0)) > 0 THEN ''
    WHEN EXISTS (
        WITH RECURSIVE character_positions(position) AS (
            SELECT 1
            UNION ALL
            SELECT position + 1
            FROM character_positions
            WHERE position < length(description)
        )
        SELECT 1
        FROM character_positions
        WHERE unicode(substr(description, position, 1)) BETWEEN 1 AND 31
           OR unicode(substr(description, position, 1)) BETWEEN 127 AND 159
        LIMIT 1
    ) THEN ''
    ELSE description
END
WHERE notes = '';

CREATE INDEX idx_assets_space_environment
ON assets(space_id, environment, id);

CREATE INDEX idx_assets_space_status
ON assets(space_id, status, id);
