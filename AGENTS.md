# AGENTS.md

kuukura is a self-hosted secrets manager for teams: a Go server (`ku-server`), a CLI (`ku`) and a website.

Read the "Repository layout" and "Rules" sections of [CONTRIBUTING.md](CONTRIBUTING.md) before moving or adding code.

## Commands

```sh
go build ./... && go vet ./...
VAULT_STORAGE=sqlite go test -race ./...
VAULT_STORAGE=postgres VAULT_TEST_POSTGRES_URL='postgres://kuukura:kuukura@localhost:55432/kuukura?sslmode=disable' go test -race ./...
gofmt -l .
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 -quiet ./...
```

The postgres run needs a container: see "Tests and checks" in CONTRIBUTING.md.

Website (`apps/web`, pnpm workspace at the root; node and pnpm come from `mise install`):

```sh
pnpm install
pnpm web:dev
pnpm --filter web check && pnpm web:build && pnpm --filter web linkcheck
```

## Design system (apps/web)

- Colors and type come from `@kuukura/brand` (`packages/brand/tokens.css`); `src/styles/tokens.css` maps them to the site's `--k-*` tokens and holds the site-only scale. Do not hard-code colors in components.
- Primitives go in `src/components/ui`, and only once two places use them.
- One component per section in `src/components/sections`.
- Motion is declared with data attributes in `src/styles/motion.css` and run by `src/scripts/motion.ts`.
- Docs content comes from `/docs` (and the root Markdown files). Never edit the generated `src/content/docs/docs`, `src/generated` or `public/brand`.

## Hard rules

- Apps import only `internal/` and `packages/`; imports never form a cycle (`arch_test.go` checks it).
- No SQL in apps; SQL lives in `internal/storage` and the domain packages.
- No `utils`, `common` or `helpers` packages.
- Brand files live only in `packages/brand`; the website imports them from there.
- Every migration is a sqlite + postgres pair in `internal/storage/migrations`; create it with `mise run db:new <name>`, never `dbmate new`.
- Fake data only in tests, fixtures and docs. Never print a secret value.
- A user-facing change gets a line under Unreleased in CHANGELOG.md and an update in `docs/`.
- Never commit binaries.
- Never write a release number in docs or templates; the tag is the version.
- Edit files with the editor tools, not shell heredocs or redirection.

[SKILL.md](skills/kuukura/SKILL.md) is the product's skill for agents that use `ku`, not instructions for you.
