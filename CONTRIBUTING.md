# Contributing to kuukura

Thanks for helping. kuukura is maintained by one person, so reviews may take a few days. A short issue before a large
change saves everyone time.

## Security first

- Found a vulnerability? Do **not** open an issue or pull request. Follow [SECURITY.md](SECURITY.md) (private
  vulnerability reporting).
- All test values, fixtures and docs use **fake** data. Never paste a real secret, token, key or invite link in an
  issue, pull request, log or screenshot.

## Setup

Tools are pinned with [mise](https://mise.jdx.dev/) (`mise.toml` selects the Go version):

```sh
mise install
go build ./...
```

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
- Sign off every commit with the [Developer Certificate of Origin](https://developercertificate.org/):
  `git commit -s`.
- Labels drive the release notes (`security`, `feature`, `bug`, `documentation`); see `.github/release.yml`.

By contributing you agree that your work is released under the [MIT license](LICENSE) and that you follow the
[Code of Conduct](CODE_OF_CONDUCT.md).
