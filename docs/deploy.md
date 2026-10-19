# Deploying kuukura (self-host with Docker)

One instance per organization. The server is one static binary in a small image; put an HTTPS reverse proxy
(Dokploy/Traefik, Caddy, ...) in front of it. The server refuses requests that did not arrive over HTTPS
(it trusts `X-Forwarded-Proto` and `X-Forwarded-For` only from private network addresses, i.e. your proxy on the
Docker network). All values below are fake examples.

## Deploy targets

kuukura is deployed from the published image `ghcr.io/victorlunam/kuukura:<version>` (releases are tagged
`YEAR.MONTH.N`, e.g. `2026.10.0`; pin one in production). Nothing is built on your server.

| Target | File | TLS | Master key |
|---|---|---|---|
| Docker Compose + Caddy (any VPS) | [`deploy/docker/docker-compose.yml`](../deploy/docker/docker-compose.yml) | Caddy (Let's Encrypt) | Docker secret file |
| Dokploy | [`deploy/dokploy/docker-compose.yml`](../deploy/dokploy/docker-compose.yml) | Dokploy's Traefik | `VAULT_MASTER_KEY` env var |
| Docker Swarm / Portainer stack | [`deploy/swarm/stack.yml`](../deploy/swarm/stack.yml) | your proxy | Swarm secret |
| Plain `docker run` | below | your proxy | Docker secret file / bind mount |

```sh
docker run -d --name kuukura --restart unless-stopped -p 127.0.0.1:8080:8080 \
  -v kuukura-data:/data -v "$PWD/secrets/master_key:/run/secrets/master_key:ro" \
  -e VAULT_DOMAIN=vault.example.com -e VAULT_MASTER_KEY_FILE=/run/secrets/master_key \
  -e VAULT_OIDC_CLIENT_ID=... -e VAULT_OIDC_CLIENT_SECRET=... \
  ghcr.io/victorlunam/kuukura:2026.10.0
```

Upgrading: change the version and redeploy (`docker compose pull && docker compose up -d`). Migrations run at start;
back up the `/data` volume (or the database) first. `ku-server version` prints the running version.

Local testing without a domain: [local-testing.md](local-testing.md).

## 1. Google login

Create an OAuth client (type "Web application") in Google Cloud. Authorized redirect URI:
`https://vault.example.com/auth/callback`. Keep the client ID and secret for step 4.

## 2. Create the master key (once)

The master key (KEK) wraps every secret's data key. It is held only in server memory. There is no unseal
command: the server reads the key at start and refuses to start without it.

```sh
mkdir -p secrets
docker run --rm -it -v "$PWD/secrets:/s" ghcr.io/victorlunam/kuukura \
  init --key-file /s/master_key --export /s/master_key.age
```

You are asked for a passphrase (12+ characters, twice). This writes:

- `secrets/master_key` - the key file (mode 0600). Mount it as a Docker secret.
- `secrets/master_key.age` - the same key, encrypted with your passphrase (age, scrypt) for **offline storage**.

Move `master_key.age` to a USB stick or print it, store the passphrase separately, and delete the `.age` file
from the server. Neither the key nor the passphrase is logged or shown again. `init` never overwrites an existing key.

Without the master key (and without the offline copy) the data cannot be read. Test the offline copy once:
`age -d secrets/master_key.age` (asks the passphrase, prints the key file body).

### AWS KMS instead

Set `VAULT_KEY_PROVIDER=aws-kms`, `VAULT_KMS_KEY_ARN=arn:aws:kms:...` and the usual AWS credentials/region
variables. Data keys are wrapped by KMS `Encrypt`/`Decrypt` with the AAD as encryption context. Keep **KMS key
deletion protection** (and a long deletion window) on: deleting the KMS key makes every secret unreadable.

## 3. Database

**SQLite (default)**: nothing to do. Data lives in the `/data` volume (WAL mode, single writer). Back up the volume
however you back up Docker volumes (backups are out of scope for kuukura itself).

**Postgres**: `VAULT_STORAGE=postgres`. Audit rows must be insert-only, which Postgres enforces with grants, so use
two roles:

1. A table **owner** role runs the migrations (`VAULT_MIGRATE_DATABASE_URL`). The first start creates the group
   role `kuukura_app` (NOLOGIN) holding the right grants (INSERT and SELECT only on `audit_log`).
2. The server connects (`VAULT_DATABASE_URL`) as a **login** role that is a member of `kuukura_app` and does not
   own the tables:
   ```sql
   CREATE ROLE kuukura_login LOGIN PASSWORD 'change-me' IN ROLE kuukura_app;
   ```
   The server refuses to start if its role could modify `audit_log`.

## 4. Configure and start

| Variable | Meaning |
|---|---|
| `VAULT_DOMAIN` | Bare domain, e.g. `vault.example.com`. Also the passkey RP ID. **Changing it invalidates every passkey** (users re-enroll via break-glass invites). |
| `VAULT_ADDR` | Listen address, default `:8080`. |
| `VAULT_STORAGE` | `sqlite` or `postgres`. |
| `VAULT_SQLITE_PATH` | SQLite file (image default `/data/kuukura.db`). |
| `VAULT_DATABASE_URL` | Postgres URL of the app login role. |
| `VAULT_MIGRATE_DATABASE_URL` | Postgres URL of the table owner, used for migrations only (defaults to `VAULT_DATABASE_URL`). |
| `VAULT_KEY_PROVIDER` | `manual` (default) or `aws-kms`. |
| `VAULT_MASTER_KEY_FILE` | Path of the key file, e.g. `/run/secrets/master_key` (preferred). |
| `VAULT_MASTER_KEY` | The key file body as an env var (for platforms such as Dokploy without Docker secrets). Visible to anyone who can read the container's environment. |
| `VAULT_KMS_KEY_ARN` | Key ARN for `aws-kms`. |
| `VAULT_OIDC_CLIENT_ID` | Google OAuth client ID. |
| `VAULT_OIDC_CLIENT_SECRET_FILE` / `VAULT_OIDC_CLIENT_SECRET` | Google OAuth client secret (file preferred). |

Configuration is validated at startup; a bad or missing value stops the server with a plain message (values are never
printed). See the files under `deploy/` for complete examples. Dokploy: create a Compose service from `deploy/dokploy/docker-compose.yml`, set the
variables above (use `VAULT_MASTER_KEY` for the key), mount a volume at `/data`, add the domain with TLS.

Monitoring: `GET /healthz` (no auth, no details; the image has a `HEALTHCHECK` using `ku-server healthcheck`) and JSON
logs on stdout (`request` lines with method, route, status, timing; never query strings, headers, bodies or values).

Shutdown is graceful (SIGTERM, 15 s). After a restart the key file is read again; there is nothing to unseal.

## 5. First admin (and break-glass)

From a terminal on the host:

```sh
docker compose exec kuukura /ku-server admin invite --email you@example.com
```

It prints a single-use link valid for **15 minutes**, bound to that Google account. Open it, sign in with Google, then
register a passkey (or an authenticator app). You get 10 recovery codes, shown once: store them. The link is never
logged and never written to the audit log. There is no HTTP bootstrap and no allowed-domain sign-up: people join only
through invites (`ku workspace invite someone@example.com`).

Lost every second factor? Run the same command for that admin's email: it issues a new 15-minute link to re-enroll.

## 6. Using it

```sh
ku profile add work --url https://vault.example.com   # the profile holds the server URL
ku login                                              # signs in to the active profile
ku secret set DATABASE_URL app:shop          # value from a hidden prompt
ku workspace grant dev@example.com write app:shop
ku link shop && ku run env:dev -- npm run dev
```

CI: create a machine token with `ku workspace invite ci-deploy --machine` (shown once), grant it `read` on the tags it
needs, and store it as `KU_TOKEN` next to `KU_URL`. A machine can do only what both its own grants and its owner's
grants allow, and can never reveal a value.

Touch ID confirmations (reveal, `--out`, `--authorize off`, secrets marked `requires_authorize`) open a browser page on
your instance and use your passkey with user verification.

## Operations

- Key rotation: see [runbook-key-rotation-drill.md](runbook-key-rotation-drill.md). Run the drill quarterly.
- Agents: see [agents.md](agents.md) for what is and is not protected.
- Security review: [asvs-l2.md](asvs-l2.md) and [threat-model.md](threat-model.md).
