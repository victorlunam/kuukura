// Package storagetest runs a test against every configured backend.
// VAULT_STORAGE selects one (sqlite|postgres); unset runs both. Postgres needs
// VAULT_TEST_POSTGRES_URL (admin URL); each test gets its own fresh database.
package storagetest

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/storage"
)

// Each calls fn once per backend with a migrated, empty database.
func Each(t *testing.T, fn func(t *testing.T, kind string, p storage.Provider)) {
	t.Helper()
	EachDSN(t, func(t *testing.T, kind, dsn string) {
		if err := storage.Migrate(kind, dsn); err != nil {
			t.Fatal(err)
		}
		p, err := storage.Open(t.Context(), kind, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		fn(t, kind, p)
	})
}

// EachDSN calls fn once per backend with the DSN of a fresh, unmigrated database, for tests that drive
// migrations themselves.
func EachDSN(t *testing.T, fn func(t *testing.T, kind, dsn string)) {
	t.Helper()
	kinds := []string{"sqlite", "postgres"}
	switch s := os.Getenv("VAULT_STORAGE"); s {
	case "":
	case "sqlite", "postgres":
		kinds = []string{s}
	default:
		t.Fatalf("bad VAULT_STORAGE %q", s)
	}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) { fn(t, kind, newDSN(t, kind)) })
	}
}

func newDSN(t *testing.T, kind string) string {
	if kind == "sqlite" {
		return filepath.Join(t.TempDir(), "kuukura.db")
	}
	admin := os.Getenv("VAULT_TEST_POSTGRES_URL")
	if admin == "" {
		t.Fatal("VAULT_TEST_POSTGRES_URL is required for the postgres backend")
	}
	name := "kt_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	exec := func(q string) {
		p, err := storage.Open(context.Background(), "postgres", admin)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		if _, err := p.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	exec("CREATE DATABASE " + name)
	t.Cleanup(func() { exec("DROP DATABASE " + name + " WITH (FORCE)") })
	u, _ := url.Parse(admin)
	u.Path = "/" + name
	return u.String()
}
