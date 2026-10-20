<p align="center">
  <img src="internal/api/web/assets/banner.svg" alt="kuukura: secrets for your team, self-hosted" width="720">
</p>

<h3 align="center">A self-hosted secrets vault for small teams. Values are decrypted only on your server.</h3>

<p align="center">
  <a href="#install-the-cli">Install</a> ·
  <a href="#quickstart-deploy-it">Deploy</a> ·
  <a href="#security">Security</a> ·
  <a href="docs/deploy.md">Docs</a> ·
  <a href="docs/agents.md">For AI agents</a>
</p>

<p align="center">
  <a href="https://github.com/victorlunam/kuukura/actions/workflows/ci.yml"><img src="https://github.com/victorlunam/kuukura/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/victorlunam/kuukura/releases/latest"><img src="https://img.shields.io/github/v/release/victorlunam/kuukura" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/victorlunam/kuukura" alt="License: MIT"></a>
  <img src="https://img.shields.io/github/go-mod/go-version/victorlunam/kuukura" alt="Go version">
  <a href="https://scorecard.dev/viewer/?uri=github.com/victorlunam/kuukura"><img src="https://api.scorecard.dev/projects/github.com/victorlunam/kuukura/badge" alt="OpenSSF Scorecard"></a>
</p>

```console
$ ku profile add work --url https://vault.example.com
$ ku login                                  # Google, then your passkey or authenticator app
$ ku secret set DATABASE_URL app:shop       # the value comes from a hidden prompt, never from an argument
$ ku link shop                              # this folder now belongs to the "shop" app
$ ku run env:dev -- npm run dev             # the command starts with DATABASE_URL in its environment
```

## Why kuukura

Teams keep secrets in `.env` files, chat messages and CI settings, and nobody can say who can read what or who
read it last week. The heavyweight vaults fix that, but they come with an operations burden (seal and unseal,
storage backends, policy languages) that a team of five to fifty does not want. kuukura is one small server with
one database and a handful of concepts: tags, grants and people. You run it, you hold the keys, and every read is
recorded in a tamper-evident log.

**It is for you if** you are one organization that wants to run its own vault, you sign in with Google, you use
CI and local development, and you want people and machines to see only the secrets they are granted.

**It is not for you if** you need dynamic (short-lived, generated) secrets, SSO/SAML sign-in (not yet: sign-in is
Google plus a second factor), several organizations on one instance, or a vendor with a support contract.
kuukura has one maintainer.

## How it works

```mermaid
flowchart LR
  subgraph Clients
    CLI["ku (CLI)"]
    CI["CI job (machine token)"]
    AGENT["AI agent via ku run"]
  end
  CLI -->|TLS| SRV
  CI -->|TLS| SRV
  AGENT -->|TLS| SRV
  SRV["ku-server: authorize, decrypt, audit"]
  SRV --> DB[("SQLite or Postgres: ciphertext and wrapped keys")]
  KEY["Master key: file, env var or AWS KMS"] --> SRV
  SRV -.->|sign-in only| GOOGLE["Google"]
  SRV -.->|confirmation page| FACTOR["Passkey or authenticator app"]
```

- **Decryption happens only on the server.** The CLI is a secure channel; it never holds a key.
- **Envelope encryption.** Every secret version gets a fresh data key (AES-256-GCM); the master key wraps the data keys.
- **The master key is not in the database.** It comes from a file or Docker secret, an environment variable, or AWS KMS.
- **Sensitive actions need your own second factor.** Reveals, file downloads and turning off confirmation open a page that shows what you are confirming.
- **Every decision is audited** in an insert-only, hash-chained log that `ku-server audit verify` checks.

## Features

- **Hand a secret to a program without handing it to a person.** `ku run -- cmd` injects environment variables; file secrets arrive as a temporary path.
- **Least privilege by default.** Read and write grants per tag, groups, and admins who manage people but have no secret access by role.
- **CI without shared passwords.** Machine tokens are limited by their own grants and their owner's, and can never reveal a value.
- **Safe with AI coding agents.** An agent skill ([SKILL.md](SKILL.md)) lets agents run commands with secrets without seeing values. Read the [limits](docs/agents.md) first.
- **Invite-only access.** Sign in with Google plus a passkey or authenticator app, with recovery codes; nobody can sign up on their own.
- **A log you can check.** `ku-server audit verify` detects edited or removed rows in the middle of the chain.
- **Guard rails in the CLI.** `ku run` refuses variable names that load code (such as `LD_PRELOAD`), and values are never accepted as arguments.
- **Works where your team works.** CLI for macOS (signed with a Developer ID, not notarized), Linux and Windows; the session lives in the system keychain or a private file.
- **Easy to run.** One container, SQLite by default, Postgres optional; templates for Docker Compose, Dokploy, Coolify, Render and Swarm.
- **Verifiable releases.** Multi-arch image with build provenance, a keyless cosign signature and an SBOM; CLI archives with checksums and provenance.

## Quickstart: deploy it

You need a domain pointing at a Linux host with Docker, and a Google OAuth client (type "Web application", redirect URI
`https://<domain>/auth/callback`). The full guide is [docs/deploy.md](docs/deploy.md).

```sh
mkdir kuukura && cd kuukura
curl -fsSLO https://raw.githubusercontent.com/victorlunam/kuukura/main/deploy/docker/docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/victorlunam/kuukura/main/deploy/docker/.env.example -o .env
# edit .env: VAULT_DOMAIN, VAULT_OIDC_CLIENT_ID, and for production set KUUKURA_VERSION to a release tag (the default is latest)

mkdir -p secrets
docker run --rm -v "$PWD/secrets:/s" ghcr.io/victorlunam/kuukura key init --key-file /s/master_key
printf '%s' 'your-google-oauth-client-secret' > secrets/oidc_client_secret
# on Linux hosts the container runs as user 65532: see "File permissions" in docs/deploy.md

docker compose up -d
docker compose exec kuukura /ku-server user invite you@example.com --admin   # open the link, sign in, register a passkey
docker compose exec -it kuukura /ku-server key show                          # once: store the key in a password manager
```

Back up the master key right away: without it nobody, including the maintainer, can read your data.

Other targets: [Dokploy](deploy/dokploy/), [Coolify](deploy/coolify/kuukura.yaml), [Docker Swarm](deploy/swarm/stack.yml),
and Render ([render.yaml](render.yaml)).

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/victorlunam/kuukura)

On Render you must set `VAULT_DOMAIN` and create the Google OAuth client for the service's address **after** the first
deploy, and the master key lives in Render's environment (copy it to your password manager). See
[docs/deploy.md](docs/deploy.md).

## Install the CLI

macOS and Linux, with Homebrew:

```sh
brew install victorlunam/tap/kuukura
```

macOS and Linux, with the install script (installs into `~/.local/bin`, checks the checksum, needs no sudo):

```sh
curl -fsSL https://raw.githubusercontent.com/victorlunam/kuukura/main/scripts/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/victorlunam/kuukura/main/scripts/install.ps1 | iex
```

Each installs `ku` and `kuukura` (the same program) for the newest release; `ku --version` prints it. You can also
download an archive from the [releases page](https://github.com/victorlunam/kuukura/releases/latest). Pinning a
version, verifying downloads, where the session is stored per system, and macOS notes: [docs/install.md](docs/install.md).

## Security

Claims are matched by where you can check them. These are self-reviews, not third-party certifications.

| What we claim | Where to verify |
|---|---|
| Threats, controls and what is not defended | [docs/threat-model.md](docs/threat-model.md) |
| Self-review against OWASP ASVS 5.0.0 Level 2 (a draft checklist, with open items listed) | [docs/asvs-l2.md](docs/asvs-l2.md) |
| Private vulnerability reporting, response targets, scope | [SECURITY.md](SECURITY.md) |
| Releases come from this repository's workflow | [Verifying a release](docs/deploy.md#verifying-a-release) |
| The audit log is a hash chain | `ku-server audit verify` |
| Static analysis and dependency checks in CI | [`ci.yml`](.github/workflows/ci.yml) (staticcheck, gosec, govulncheck) |

Releases are built by [`release.yml`](.github/workflows/release.yml) with build provenance, a keyless cosign
signature and an SBOM. Check what you pull with the GitHub CLI and cosign v3 or later (set `v` to the release you run,
for example from the [releases page](https://github.com/victorlunam/kuukura/releases)):

```sh
v=YEAR.MONTH.N
gh attestation verify oci://ghcr.io/victorlunam/kuukura:$v --repo victorlunam/kuukura
cosign verify ghcr.io/victorlunam/kuukura:$v \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/victorlunam/kuukura/.github/workflows/release.yml@refs/tags/v$v
```

These prove an artifact came from this repository's workflow at that tag; they do not prove the source has no bugs.

### What kuukura does not protect against

- **Someone who has both the database and the master key** reads everything. That is why the key lives outside the database and `/data`, and why platforms that keep it in an environment variable weaken this.
- **A compromised server host.** Root access, a debugger or a memory dump exposes keys and plaintext while the server is running.
- **A malicious admin with host or database access**, who can mint invites, replace the binary or rewrite the audit chain.
- **A stolen session on an unlocked laptop** can `ku run` plain secrets until it expires (8 hours, 1 hour idle); reveals still need your second factor.
- **AI agents that print what `ku run` injects.** Give agents low-value development secrets only ([details](docs/agents.md)).
- **Phishing of authenticator codes and recovery codes**, which passkeys resist and these do not.

## How it compares

| | Hosting | Strengths | Choose it if |
|---|---|---|---|
| **kuukura** | Self-hosted, one organization | Small, simple model; server-side decryption with per-person confirmation; no unseal step | You are one small team and want a vault you can operate in an afternoon |
| [Infisical](https://github.com/Infisical/infisical) | Self-hosted or cloud | MIT core; dynamic secrets listed among its features; paid enterprise edition under `ee` | You want a broader platform and can use its enterprise tier where needed |
| [OpenBao](https://github.com/openbao/openbao) | Self-hosted | MPL-2.0; dynamic secrets with leases and revocation; encrypts before writing to storage | You need dynamic credentials, many backends or large-scale policy |
| [SOPS](https://github.com/getsops/sops) | A file tool, no server | MPL-2.0; encrypts YAML, JSON, ENV, INI and binary files; AWS/GCP/Azure KMS, age, PGP | Your secrets live in Git and you do not need access logs or per-person grants |
| `.env` files | None | Zero setup | Throwaway local work with nothing worth protecting |

Sources, last checked 2026-10-19: the repository pages linked above (licenses and feature lists as stated by each
project). Doppler is not listed because its self-hosting status could not be confirmed from its public pages.
Please open an issue if a row is out of date.

## Status

kuukura uses calendar versions (`YEAR.MONTH.N`; see the [changelog](CHANGELOG.md)) and has a single maintainer. The core model
(encryption, grants, audit, the CLI and server commands) is implemented and covered by tests on SQLite and Postgres in
CI. Not yet: SSO/SAML, dynamic secrets, multi-organization instances, a third-party security audit, and a full
requirement-by-requirement ASVS mapping (the checklist is a draft). Pin a release in production, read the release notes
before upgrading, and back up the database and the master key first.

## FAQ

**Why not Vault or OpenBao?** They do more, including dynamic secrets, and cost more to run. kuukura trades breadth for a
small system you can understand and operate, with no unseal ceremony. If you need their features, use them.

**What if I lose my passkey?** Use a recovery code (you get ten at enrollment). If you lost those too, someone with a shell on
the server runs `ku-server user reset-factors you@example.com` and you enroll again through a 15-minute link.

**How do I back up?** Back up the database (the `/data` volume or Postgres) and the master key as two different things in two
different places. Run `ku-server key show` once per key version and keep the text in a password manager; the key file lives
in its own `/keys` volume.

**Can an AI agent see values?** Not through the commands it is taught: `ku run` injects them, and reveals need your passkey or
code. But a command it runs can print its own environment. Treat that as accepted risk and use low-value secrets
([docs/agents.md](docs/agents.md)).

**What if the server is down?** `ku run` cannot fetch secrets until it is back, because values are decrypted only on the server. The server restarts
by reading the key again; there is nothing to unseal. Run it as a restartable container with its volumes backed up.

**Is there a hosted version?** No. You run it yourself.

**Can several organizations share one instance?** No. It is one instance per organization.

**Can I use Postgres?** Yes: set `VAULT_STORAGE=postgres`. The audit log is insert-only, enforced with database grants
([setup](docs/deploy.md#3-database)). SQLite is the default.

## Development

```sh
mise install                                   # pinned Go version
VAULT_STORAGE=sqlite go test -race ./...

docker run -d -e POSTGRES_PASSWORD=kuukura -e POSTGRES_USER=kuukura -p 55432:5432 postgres:17
VAULT_STORAGE=postgres \
VAULT_TEST_POSTGRES_URL='postgres://kuukura:kuukura@localhost:55432/kuukura?sslmode=disable' \
  go test -race ./...
```

Local login with a real Google account: [docs/local-testing.md](docs/local-testing.md). The HTTP API:
[docs/api.md](docs/api.md). All values in tests, fixtures and docs are fake.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE), Copyright (c) 2026 Victor Luna.
