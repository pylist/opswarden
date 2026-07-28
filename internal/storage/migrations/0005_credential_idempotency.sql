ALTER TABLE idempotency_records
ADD COLUMN request_hash TEXT
CHECK (request_hash IS NULL OR length(request_hash) = 64);

ALTER TABLE idempotency_records
ADD COLUMN resource_id TEXT;

ALTER TABLE idempotency_records
ADD COLUMN resource_version INTEGER
CHECK (resource_version IS NULL OR resource_version > 0);

UPDATE idempotency_records
SET
    request_hash = json_extract(CAST(response_headers AS TEXT), '$.request_hash'),
    resource_id = json_extract(CAST(response_headers AS TEXT), '$.resource_id'),
    resource_version = json_extract(CAST(response_headers AS TEXT), '$.version')
WHERE
    response_headers IS NOT NULL
    AND json_valid(CAST(response_headers AS TEXT))
    AND length(json_extract(CAST(response_headers AS TEXT), '$.request_hash')) = 64
    AND length(json_extract(CAST(response_headers AS TEXT), '$.resource_id')) > 0
    AND json_type(CAST(response_headers AS TEXT), '$.version') = 'integer'
    AND json_extract(CAST(response_headers AS TEXT), '$.version') > 0;

CREATE TRIGGER idempotency_explicit_result_required
BEFORE INSERT ON idempotency_records
WHEN
    NEW.request_hash IS NULL
    OR length(NEW.request_hash) <> 64
    OR NEW.resource_id IS NULL
    OR length(NEW.resource_id) = 0
    OR NEW.resource_version IS NULL
    OR NEW.resource_version <= 0
    OR NEW.response_status < 200
    OR NEW.response_status > 299
BEGIN
    SELECT RAISE(ABORT, 'idempotency result fields are required');
END;
