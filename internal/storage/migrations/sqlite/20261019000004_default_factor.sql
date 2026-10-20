-- migrate:up
-- One second factor per account is the default: the page offers it first. Existing accounts get their oldest.
ALTER TABLE credentials ADD COLUMN is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0,1));
UPDATE credentials SET is_default = 1 WHERE id IN (
  SELECT c.id FROM credentials c WHERE NOT EXISTS (
    SELECT 1 FROM credentials o WHERE o.principal_id = c.principal_id
      AND (o.created_at < c.created_at OR (o.created_at = c.created_at AND o.id < c.id))));
CREATE UNIQUE INDEX credentials_one_default ON credentials (principal_id) WHERE is_default = 1;

-- migrate:down
DROP INDEX credentials_one_default;
ALTER TABLE credentials DROP COLUMN is_default;
