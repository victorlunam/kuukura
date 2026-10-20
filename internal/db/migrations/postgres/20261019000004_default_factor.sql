-- migrate:up
-- One second factor per account is the default: the page offers it first. Existing accounts get their oldest.
ALTER TABLE credentials ADD COLUMN is_default boolean NOT NULL DEFAULT false;
UPDATE credentials SET is_default = true WHERE id IN (
  SELECT DISTINCT ON (principal_id) id FROM credentials ORDER BY principal_id, created_at, id);
CREATE UNIQUE INDEX credentials_one_default ON credentials (principal_id) WHERE is_default;

-- migrate:down
DROP INDEX credentials_one_default;
ALTER TABLE credentials DROP COLUMN is_default;
