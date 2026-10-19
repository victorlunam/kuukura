-- migrate:up
CREATE TABLE principals (
  id uuid PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('human','machine')),
  name text NOT NULL UNIQUE,
  email text,
  owner_id uuid REFERENCES principals(id),
  role text CHECK (role IN ('admin','member')),
  status text NOT NULL CHECK (status IN ('invited','active','disabled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((kind = 'human' AND role IS NOT NULL AND owner_id IS NULL)
      OR (kind = 'machine' AND role IS NULL AND email IS NULL))
);

CREATE TABLE identities (
  id uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES principals(id),
  provider text NOT NULL,
  subject text NOT NULL,
  email text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, subject)
);

CREATE TABLE credentials (
  id uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES principals(id),
  kind text NOT NULL CHECK (kind IN ('passkey','totp')),
  public_key bytea,
  encrypted_totp_secret bytea,
  sign_count integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  CHECK ((kind = 'passkey' AND public_key IS NOT NULL AND encrypted_totp_secret IS NULL)
      OR (kind = 'totp' AND encrypted_totp_secret IS NOT NULL AND public_key IS NULL))
);

CREATE TABLE recovery_codes (
  id uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES principals(id),
  code_hash bytea NOT NULL,
  used_at timestamptz
);

CREATE TABLE tokens (
  id uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES principals(id),
  kind text NOT NULL CHECK (kind IN ('session','machine_key','invite')),
  scopes text[] NOT NULL DEFAULT '{}',
  token_hash bytea NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  last_used_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE secrets (
  id uuid PRIMARY KEY,
  name text NOT NULL CHECK (name = upper(name)),
  kind text NOT NULL CHECK (kind IN ('text','file')),
  description text NOT NULL DEFAULT '',
  tags text[] NOT NULL DEFAULT '{}' CHECK (cardinality(tags) <= 10),
  requires_authorize boolean NOT NULL DEFAULT false,
  current_version_id uuid,
  created_by uuid NOT NULL REFERENCES principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  archived_at timestamptz,
  archived_by uuid REFERENCES principals(id)
);
CREATE UNIQUE INDEX secrets_name_tags_active ON secrets (name, tags) WHERE archived_at IS NULL;
CREATE INDEX secrets_tags_gin ON secrets USING GIN (tags);

CREATE TABLE secret_versions (
  id uuid PRIMARY KEY,
  secret_id uuid NOT NULL REFERENCES secrets(id),
  number integer NOT NULL,
  ciphertext bytea NOT NULL,
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
  wrapped_key bytea NOT NULL,
  key_id text NOT NULL,
  format_version smallint NOT NULL DEFAULT 1,
  filename text,
  created_by uuid NOT NULL REFERENCES principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  compromised_at timestamptz,
  compromised_by uuid REFERENCES principals(id),
  UNIQUE (secret_id, number)
);

ALTER TABLE secrets ADD CONSTRAINT secrets_current_version_fk
  FOREIGN KEY (current_version_id) REFERENCES secret_versions(id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE groups (
  id uuid PRIMARY KEY,
  name text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE group_members (
  group_id uuid NOT NULL REFERENCES groups(id),
  principal_id uuid NOT NULL REFERENCES principals(id),
  PRIMARY KEY (group_id, principal_id)
);

CREATE TABLE grants (
  id uuid PRIMARY KEY,
  subject_type text NOT NULL CHECK (subject_type IN ('principal','group')),
  subject_id uuid NOT NULL,
  tag_selector text[] NOT NULL DEFAULT '{}',
  permission text NOT NULL CHECK (permission IN ('read','write')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX grants_subject ON grants (subject_type, subject_id);

CREATE TABLE audit_log (
  id uuid PRIMARY KEY,
  at timestamptz NOT NULL,
  principal_id uuid NOT NULL REFERENCES principals(id),
  action text NOT NULL CHECK (action IN ('login','login_failed','create','read','list','describe','update',
    'mark_compromised','revoke_token','token_create','invite','grant','revoke_grant','role_change','disable',
    'key_rotate','archive','reveal','group_add','group_remove')),
  secret_id uuid,
  version integer,
  result text NOT NULL CHECK (result IN ('ok','denied')),
  ip inet,
  target_type text CHECK (target_type IN ('principal','group','grant','token','key')),
  target_id uuid,
  metadata jsonb,
  prev_hash bytea NOT NULL,
  hash bytea NOT NULL
);

-- migrate:down
DROP TABLE audit_log, grants, group_members, groups;
ALTER TABLE secrets DROP CONSTRAINT secrets_current_version_fk;
DROP TABLE secret_versions, secrets, tokens, recovery_codes, credentials, identities, principals;
