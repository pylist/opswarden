ALTER TABLE users
ADD COLUMN system_role TEXT NOT NULL DEFAULT 'member'
CHECK (system_role IN ('system_owner', 'system_admin', 'member'));

ALTER TABLE user_totp
ADD COLUMN last_used_counter INTEGER
CHECK (last_used_counter IS NULL OR last_used_counter >= 0);

ALTER TABLE sessions
ADD COLUMN idle_expires_at TEXT;

ALTER TABLE sessions
ADD COLUMN recent_totp_at TEXT;
