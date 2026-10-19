-- migrate:up
-- The app must connect as a login role that is a member of kuukura_app and does NOT own the tables,
-- otherwise these grants do not bind it.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kuukura_app') THEN
    CREATE ROLE kuukura_app NOLOGIN;
  END IF;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON principals, identities, credentials, recovery_codes, tokens,
  secrets, secret_versions, groups, group_members, grants TO kuukura_app;
GRANT SELECT, INSERT ON audit_log TO kuukura_app;

-- migrate:down
-- The role itself is cluster-wide and is left in place.
REVOKE ALL ON principals, identities, credentials, recovery_codes, tokens,
  secrets, secret_versions, groups, group_members, grants, audit_log FROM kuukura_app;
