-- migrate:up
CREATE TABLE principals (
  id TEXT PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('human','machine')),
  name text NOT NULL UNIQUE,
  email text,
  owner_id TEXT REFERENCES principals(id),
  role text CHECK (role IN ('admin','member')),
  status text NOT NULL CHECK (status IN ('invited','active','disabled')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  CHECK ((kind = 'human' AND role IS NOT NULL AND owner_id IS NULL)
      OR (kind = 'machine' AND role IS NULL AND email IS NULL))
);

CREATE TABLE identities (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  provider text NOT NULL,
  subject text NOT NULL,
  email text NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  UNIQUE (provider, subject)
);

CREATE TABLE credentials (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  kind text NOT NULL CHECK (kind IN ('passkey','totp')),
  public_key BLOB,
  encrypted_totp_secret BLOB,
  sign_count integer NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  last_used_at TEXT,
  CHECK ((kind = 'passkey' AND public_key IS NOT NULL AND encrypted_totp_secret IS NULL)
      OR (kind = 'totp' AND encrypted_totp_secret IS NOT NULL AND public_key IS NULL))
);

CREATE TABLE recovery_codes (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  code_hash BLOB NOT NULL,
  used_at TEXT
);

CREATE TABLE tokens (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  kind text NOT NULL CHECK (kind IN ('session','machine_key','invite')),
  scopes TEXT NOT NULL DEFAULT ',',
  token_hash BLOB NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE secrets (
  id TEXT PRIMARY KEY,
  name text NOT NULL CHECK (name = upper(name)),
  kind text NOT NULL CHECK (kind IN ('text','file')),
  description text NOT NULL DEFAULT '',
  tags TEXT NOT NULL DEFAULT ',',
  requires_authorize INTEGER NOT NULL DEFAULT 0 CHECK (requires_authorize IN (0,1)),
  current_version_id TEXT REFERENCES secret_versions(id) DEFERRABLE INITIALLY DEFERRED,
  created_by TEXT NOT NULL REFERENCES principals(id),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  archived_at TEXT,
  archived_by TEXT REFERENCES principals(id)
);
CREATE UNIQUE INDEX secrets_name_tags_active ON secrets (name, tags) WHERE archived_at IS NULL;

CREATE TABLE secret_versions (
  id TEXT PRIMARY KEY,
  secret_id TEXT NOT NULL REFERENCES secrets(id),
  number integer NOT NULL,
  ciphertext BLOB NOT NULL,
  nonce BLOB NOT NULL CHECK (length(nonce) = 12),
  wrapped_key BLOB NOT NULL,
  key_id text NOT NULL,
  format_version INTEGER NOT NULL DEFAULT 1,
  filename text,
  created_by TEXT NOT NULL REFERENCES principals(id),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  compromised_at TEXT,
  compromised_by TEXT REFERENCES principals(id),
  UNIQUE (secret_id, number)
);

CREATE TABLE groups (
  id TEXT PRIMARY KEY,
  name text NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE group_members (
  group_id TEXT NOT NULL REFERENCES groups(id),
  principal_id TEXT NOT NULL REFERENCES principals(id),
  PRIMARY KEY (group_id, principal_id)
);

CREATE TABLE grants (
  id TEXT PRIMARY KEY,
  subject_type text NOT NULL CHECK (subject_type IN ('principal','group')),
  subject_id TEXT NOT NULL,
  tag_selector TEXT NOT NULL DEFAULT ',',
  permission text NOT NULL CHECK (permission IN ('read','write')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX grants_subject ON grants (subject_type, subject_id);

CREATE TABLE audit_log (
  id TEXT PRIMARY KEY,
  at TEXT NOT NULL,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  action text NOT NULL CHECK (action IN ('login','login_failed','create','read','list','describe','update',
    'mark_compromised','revoke_token','token_create','invite','grant','revoke_grant','role_change','disable',
    'key_rotate','archive','reveal','group_add','group_remove')),
  secret_id TEXT,
  version integer,
  result text NOT NULL CHECK (result IN ('ok','denied')),
  ip TEXT,
  target_type text CHECK (target_type IN ('principal','group','grant','token','key')),
  target_id TEXT,
  metadata TEXT,
  prev_hash BLOB NOT NULL,
  hash BLOB NOT NULL
);

-- migrate:down
DROP TABLE audit_log;
DROP TABLE grants;
DROP TABLE group_members;
DROP TABLE groups;
DROP TABLE secret_versions;
DROP TABLE secrets;
DROP TABLE tokens;
DROP TABLE recovery_codes;
DROP TABLE credentials;
DROP TABLE identities;
DROP TABLE principals;
