# kuukura

Self-hosted secrets vault for one organization. Server `ku-server`, CLI `kuukura` (alias `ku`).
Decryption happens only on the server; the CLI is a secure channel. Values are never accepted as CLI arguments.

```sh
ku login --url https://vault.example.com
ku secret set DATABASE_URL app:shop      # hidden prompt
ku link shop && ku run env:dev -- npm run dev
```

- Deploy with Docker: [docs/deploy.md](docs/deploy.md) (`Dockerfile`, `docker-compose.yml`)
- API: [docs/api.md](docs/api.md)
- Key rotation drill: [docs/runbook-key-rotation-drill.md](docs/runbook-key-rotation-drill.md)
- Coding agents: [SKILL.md](SKILL.md), [docs/agents.md](docs/agents.md)
- Security: [docs/asvs-l2.md](docs/asvs-l2.md), [docs/threat-model.md](docs/threat-model.md)

Development: `go test -race ./...` runs every backend (set `VAULT_STORAGE=sqlite|postgres` to pick one; Postgres needs
`VAULT_TEST_POSTGRES_URL`, an admin URL, e.g. `docker run -d -e POSTGRES_PASSWORD=kuukura -e POSTGRES_USER=kuukura -p 55432:5432 postgres:17`
and `postgres://kuukura:kuukura@localhost:55432/kuukura?sslmode=disable`). All values in tests, fixtures and docs are fake.
