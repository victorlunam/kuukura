# Changelog

All notable changes to kuukura are listed here, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are calendar versions (`YEAR.MONTH.N`).
A release is a tag: its section is copied into the GitHub release notes.

## [Unreleased]

### Security

- Releases carry build provenance, a keyless cosign signature on the image and an SBOM; CI tools and actions are
  pinned by version or SHA.
- `ku run` refuses secret names that load code (`LD_PRELOAD`, `DYLD_*`, `PATH`, `NODE_OPTIONS`, `PYTHONPATH`,
  `BASH_ENV` and a few more) and forwards only `TERM` and `HUP` to the command.
- `ku` opens links from the server in the browser only when they point at the profile's own server.
- Unknown `--flags` are rejected; an argument with a colon that is not a valid `key:value` tag is refused and never
  echoed back.
- The master key is checked at start-up: the server refuses a key that cannot open the data, and start-up errors name
  their cause without credentials.
- A secret the caller may not read behaves like a missing one; the denial is still audited.
- The audit log hashes the canonical form of the client IP (other forms verify as tampering).
- Confirmations have their own rate limit; failed confirmations are audited; an enrollment code cannot be replayed.
- A database error while checking admin rights is reported instead of being treated as a denial.
- Postgres: a role that is a member of the table owner is refused.

### Added

- `ku-server` commands as `noun verb`: `key init|rotate|show`, `user list|invite|disable|enable|reset-factors`,
  `audit verify`. Host actions are audited under a reserved `ku-server` principal.
- The server can generate the master key on first start (`VAULT_MASTER_KEY_GENERATE`); `key show` prints it once per
  version. A bare base64 or hex key is accepted.
- `ku workspace enable` (and enabling a person through the API), next to `disable`.
- `ku-server audit verify` prints the row count and head hash.
- Deploy templates for Dokploy, Coolify and Render that generate the master key; `/keys` in the image.
- Install scripts for macOS, Linux and Windows (`scripts/install.sh`, `scripts/install.ps1`) and a Homebrew tap
  (`brew install victorlunam/tap/kuukura`).
- Public project files: README, LICENSE, contributing guide, issue and pull request templates, release notes
  configuration, social preview, SECURITY.md, OpenSSF Scorecard.
- Docs: API problem table, key rotation by new KMS ARN, release verification, exit codes.

### Changed

- Passkeys and authenticator apps are called that in every page, message and doc (the commands call them factors);
  "second step" is gone. The API problem code `second-factor-required` is now `factor-required`.
- `ku` and `ku-server` share one error style: `ku` prints `✗ Sentence.` and, when one command fixes it,
  `  Run: <command>`; `ku-server` prints `ku-server: Sentence.`. Wrong arguments print the command's own usage line and
  exit 2. Both helps list one `noun verb` line per command.
- `ku` status lines go to stderr, so stdout carries only data.
- Key rotation and its audit row commit together; `rotate-key` is audited with the rewrap.
- Invite expiry is shown in RFC 3339.
- CI runs the SQLite and Postgres tests as separate jobs; releases are built with Go 1.26.
- Illustrations and the wordmark share one drawing system.

### Fixed

- Concurrent secret updates lose cleanly with a retryable clash instead of failing.
- The last second factor survives concurrent removals.
- KMS reads data under its stored ARN, so rotation by a new ARN works; wrap errors keep the AWS error code.
- An unreadable session is no longer reported as logged out; `ku login` saves the session before the page says
  signed in.
- Problem responses are really sent as `application/problem+json`.
- The confirmation page says what it confirms; the add-factor link needs its button.

### Removed

- `ku workspace remove`, replaced by `disable` and `enable`.
- The age export of the master key (`key show` replaces it).
- `second-factor-required` (see `factor-required`).

## [2026.10.1] - 2026-10-19

### Added

- One second factor is the default: sign-in and confirmation pages offer its method first
  (`ku account factor default <id>`); removing it hands the mark to another factor.

## [2026.10.0] - 2026-10-19

First release.

### Added

- Server: secrets with envelope encryption (AES-256-GCM data keys wrapped by a master key from a file, an environment
  variable or AWS KMS), key rotation, an insert-only hash-chained audit log, per-tag read and write grants, groups and
  admins, invite-only accounts, SQLite and Postgres storage.
- Sign-in with Google (OIDC), passkeys, authenticator apps (TOTP) and recovery codes; confirmation pages for reveals,
  file downloads and turning confirmation off.
- `ku` CLI for macOS, Linux and Windows: profiles, `login`, `secret`, `workspace`, `account factor`, `link`,
  `run -- cmd` to inject secrets as environment variables or temporary files; the session lives in the system keychain
  or a private file.
- Machine tokens for CI, limited by their own grants and their owner's, never able to reveal a value.
- Agent skill (`SKILL.md`), Dockerfile, deploy templates for Docker Compose with Caddy, Dokploy and Docker Swarm,
  release workflow, local development mode, threat model and an ASVS level 2 checklist.
- macOS binaries signed with a Developer ID when the signing secrets exist.

[Unreleased]: https://github.com/victorlunam/kuukura/compare/v2026.10.1...HEAD
[2026.10.1]: https://github.com/victorlunam/kuukura/compare/v2026.10.0...v2026.10.1
[2026.10.0]: https://github.com/victorlunam/kuukura/releases/tag/v2026.10.0
