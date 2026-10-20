# Contributing to kuukura

Thanks for helping. kuukura is maintained by one person, so reviews may take a few days. A short issue before a large
change saves everyone time.

## Security first

- Found a vulnerability? Do **not** open an issue or pull request. Follow [SECURITY.md](SECURITY.md) (private
  vulnerability reporting).
- All test values, fixtures and docs use **fake** data. Never paste a real secret, token, key or invite link in an
  issue, pull request, log or screenshot.

## Repository layout

```
apps/
  ku/               the CLI client
  ku-server/        the server and the operator CLI
    api/            HTTP layer: handlers, problem+json, rate limit, the server's pages (page.html, style.css, app.js)
  web/              the website and docs site (Astro + Starlight, a pnpm workspace package)
internal/           Go code shared by the Go apps
  access/ audit/ auth/ identity/ keys/ masterkey/ secrets/   domain packages
  storage/          the only code with SQL, and the migrations (migrations/{sqlite,postgres})
  cli/              the few conventions both CLIs share (exit codes, usage error, Sentence)
packages/           shared across languages, or JS packages
  brand/            the brand: logos, art, sprite, tokens.css (Go embeds it, the website imports it)
deploy/ docs/ scripts/ .github/
```

- `apps/` holds the programs; each is built and shipped on its own.
- `internal/` is Go code that more than one Go app needs. Go itself stops other modules from importing it.
- `packages/` is what is shared across languages (Go and TypeScript), such as the brand, a future API contract or
  TypeScript libraries.
- `deploy/` and `scripts/` stay at the root: public raw URLs point into them.

### Dependency rules

`arch_test.go` enforces these on every `go test ./...`:

1. An app never imports another app (`apps/ku-server/api` is part of `apps/ku-server`).
2. `internal/` and `packages/` never import `apps/`.
3. `apps/ku` imports no domain package, only `internal/cli`: it talks to the server over HTTP.
4. Domain layering goes downward only, no cycles: `storage` and `keys` are leaves; `audit` uses `storage`; `access`
   uses `audit`, `storage`; `auth` uses `audit`, `keys`, `storage`; `secrets` uses `access`, `audit`, `keys`,
   `storage`; `identity` uses `access`, `audit`, `auth`, `storage`; `masterkey` (key rotation and the start-up key
   check, which span `secrets` and `auth`) uses `audit`, `auth`, `keys`, `secrets`, `storage`.
5. `internal/cli` and `packages/brand` import only the standard library.
6. `database/sql` is imported only by `internal/storage` and the domain packages above, never by an app.

### Rules

- Code starts inside the app that needs it and moves to `internal/` or `packages/` when a second app needs it.
- No `utils`, `common` or `helpers` packages; name a package after what it does for the product.
- SQL lives only in `internal/storage`-style domain packages, never in apps.
- Migrations always come as a pair, one for sqlite and one for postgres, in `internal/storage/migrations` (`mise run db:new <name>`).
- Brand files live only in `packages/brand`.
- Minimalism: start small. Propose bigger features (for example a search with many filters) in an issue first.

### Adding a capability

1. A new `internal/<capability>` package, placed in the layering above (add it to `arch_test.go`).
2. A migration pair in `internal/storage/migrations/{sqlite,postgres}`: `mise run db:new <name>` writes both files
   with dbmate's timestamp and the `-- migrate:up` / `-- migrate:down` skeleton (do not run a plain `dbmate new`: its
   default folder is `db/migrations`).
3. The handler in `apps/ku-server/api`.
4. The command in `apps/ku`.
5. A docs page under `docs/`.
6. A line under `Unreleased` in [CHANGELOG.md](CHANGELOG.md).

## Setup

Tools are pinned with [mise](https://mise.jdx.dev/) (`mise.toml` selects the Go, Node and pnpm versions):

```sh
mise install
go build ./...
pnpm install          # the pnpm workspace: apps/web and packages/brand
pnpm web:dev          # the website, with live reload
pnpm web:build        # the static site into apps/web/dist
```

`pnpm web:check` type-checks the site; CI also runs `pnpm --filter web linkcheck`. The site builds its docs pages from
`docs/` and the other Markdown files at the root, and its brand files from `packages/brand`
(`apps/web/scripts/sync.mjs`); edit those sources, never the generated copies.

## Tests and checks

`go test -race ./...` runs every storage backend; set `VAULT_STORAGE` to pick one.

```sh
VAULT_STORAGE=sqlite go test -race ./...

docker run -d -e POSTGRES_PASSWORD=kuukura -e POSTGRES_USER=kuukura -p 55432:5432 postgres:17
VAULT_STORAGE=postgres \
VAULT_TEST_POSTGRES_URL='postgres://kuukura:kuukura@localhost:55432/kuukura?sslmode=disable' \
  go test -race ./...
```

CI also runs `staticcheck`, `gosec` and `govulncheck` (versions are pinned in `.github/workflows/ci.yml`):

```sh
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 ./...
```

## Pull requests

- Keep a change focused; add or update tests, on both backends when storage is touched.
- Update the docs under `docs/` when behavior changes.
- User-facing changes get a line under `Unreleased` in [CHANGELOG.md](CHANGELOG.md). Never write a release number in
  docs or templates: the tag is the version and CI builds everything from it.
- Sign off every commit with the [Developer Certificate of Origin](https://developercertificate.org/):
  `git commit -s`.
- Labels drive the release notes (`security`, `feature`, `bug`, `documentation`); see `.github/release.yml`.

By contributing you agree that your work is released under the [MIT license](LICENSE) and that you follow the
[Code of Conduct](CODE_OF_CONDUCT.md).
