ALTER TABLE space_memberships
ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0);
