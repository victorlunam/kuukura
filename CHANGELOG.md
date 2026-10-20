# Changelog

All notable changes to kuukura are listed here, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are calendar versions (`YEAR.MONTH.N`).
A release is a tag: its section is copied into the GitHub release notes.

## [Unreleased]

### Fixed

- `ku secret` commands now use the linked folder's app tag, like `ku run`; a denied write says which tags and how to
  get access.

## [2026.10.8] - 2026-10-20

### Security

- A CLI sign-in link works once: after the sign-in completes, reopening it shows 'already used' instead of starting
  another sign-in.

## [2026.10.7] - 2026-10-20

### Fixed

- Behind Cloudflare, the invite and sign-in pages showed "[email protected]": addresses are now marked so a CDN's email
  obfuscation leaves them alone (its decoding script is, correctly, blocked by the pages' CSP).
- Docs: deploying behind a cloud load balancer that terminates TLS, and HTTPS behind Cloudflare.

## [2026.10.6] - 2026-10-20

### Added

- A page at `/` that shows how to connect the CLI; a readable page when a browser reaches the server over plain HTTP.

### Fixed

- The image includes a minimal shell (busybox) so platform terminals (Dokploy, Coolify) can run `ku-server` commands.

## [2026.10.5] - 2026-10-20

### Changed

- Release images build much faster: Go cross-compiles for arm64 instead of running under emulation, with layer caching.

## [2026.10.4] - 2026-10-20

### Security

- `golang.org/x/crypto` v0.58.0; SECURITY.md explains the one govulncheck advisory that does not apply.
- Website: strict Content-Security-Policy and HSTS.

### Added

- Install scripts are tested on macOS, Linux and Windows (PowerShell 7 and 5.1) on every change and weekly.

### Fixed

- Deploy templates, checked by running them: render.yaml uses the current plan id `0.5c-512mb` and Render's port 10000; the Swarm stack documents the `proxy` network it requires; the Dokploy and Coolify docs say what the platform leaves to you (HTTPS and `VAULT_DOMAIN` on Dokploy, a bare domain on Coolify).

## [2026.10.3] - 2026-10-20

### Added

- Website and docs site (apps/web, Astro + Starlight), deployed to Cloudflare Workers:
  https://kuukura-main-landing.neodev-f72.workers.dev
- `mise run db:new <name>` creates a migration pair (sqlite and postgres).

### Changed

- Repository layout: apps/ (ku, ku-server, web), internal/ (shared Go code), packages/ (brand, shared across languages); conventions in CONTRIBUTING.md and AGENTS.md, enforced by a dependency-rules test.
- Code organized by capability: one concern per file; key rotation and start-up key checks live in internal/masterkey.
- Install scripts and the Homebrew formula build from the same tag as everything else; no release number is written in docs.

### Removed

- Two build artifacts that had been committed by mistake.

## [2026.10.2] - 2026-10-20

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
- The image's base images are pinned by digest and kept current by Dependabot.

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
- A new brand: a vault-door mark, one palette and geometry for the logo, favicon, banner, illustrations and icons.
- The Go domain packages live under `internal/`; `cmd/` holds the two binaries.
- `github.com/fxamacker/cbor/v2` 2.9.6.

### Fixed

- Concurrent secret updates lose cleanly with a retryable clash instead of failing.
- Removing factors at the same time always leaves the account at least one.
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

[Unreleased]: https://github.com/victorlunam/kuukura/compare/v2026.10.8...HEAD
[2026.10.8]: https://github.com/victorlunam/kuukura/compare/v2026.10.7...v2026.10.8
[2026.10.7]: https://github.com/victorlunam/kuukura/compare/v2026.10.6...v2026.10.7
[2026.10.6]: https://github.com/victorlunam/kuukura/compare/v2026.10.5...v2026.10.6
[2026.10.5]: https://github.com/victorlunam/kuukura/compare/v2026.10.4...v2026.10.5
[2026.10.4]: https://github.com/victorlunam/kuukura/compare/v2026.10.3...v2026.10.4
[2026.10.3]: https://github.com/victorlunam/kuukura/compare/v2026.10.2...v2026.10.3
[2026.10.2]: https://github.com/victorlunam/kuukura/compare/v2026.10.1...v2026.10.2
[2026.10.1]: https://github.com/victorlunam/kuukura/compare/v2026.10.0...v2026.10.1
[2026.10.0]: https://github.com/victorlunam/kuukura/releases/tag/v2026.10.0
