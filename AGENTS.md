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

## Hard rules

- Apps import only `internal/` and `packages/`; imports never form a cycle (`arch_test.go` checks it).
- No SQL in apps; SQL lives in `internal/storage` and the domain packages.
- No `utils`, `common` or `helpers` packages.
- Brand files live only in `packages/brand`.
- Every migration is a sqlite + postgres pair in `internal/storage/migrations`; create it with `mise run db:new <name>`, never `dbmate new`.
- Fake data only in tests, fixtures and docs. Never print a secret value.
- A user-facing change gets a line under Unreleased in CHANGELOG.md and an update in `docs/`.
- Never commit binaries.
- Never write a release number in docs or templates; the tag is the version.
- Edit files with the editor tools, not shell heredocs or redirection.

[SKILL.md](SKILL.md) is the product's skill for agents that use `ku`, not instructions for you.
