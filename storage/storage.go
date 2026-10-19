// Package storage is the pluggable database layer: sqlite or postgres.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/amacneil/dbmate/v2/pkg/dbmate"
	_ "github.com/amacneil/dbmate/v2/pkg/driver/postgres"
	"net/url"

	kdb "github.com/victorlunam/kuukura/db"
)

// Provider hides the dialect differences. Queries are written with `?`
// placeholders and passed through Rebind.
type Provider interface {
	DB() *sql.DB
	Rebind(query string) string
	// TagsArg encodes tags as a query argument for a tags column.
	TagsArg(t Tags) any
	// Contains returns a SQL condition (and its args) true when every tag of
	// sel is contained in the tags column col.
	Contains(col string, sel Tags) (cond string, args []any)
	Close() error
}

// Open connects to the backend. kind is "sqlite" (dsn = file path) or
// "postgres" (dsn = connection URL).
func Open(ctx context.Context, kind, dsn string) (Provider, error) {
	switch kind {
	case "sqlite":
		return openSQLite(ctx, dsn)
	case "postgres":
		return openPostgres(ctx, dsn)
	}
	return nil, fmt.Errorf("storage: unknown VAULT_STORAGE %q (want sqlite|postgres)", kind)
}

func migrator(kind, dsn string) (*dbmate.DB, error) {
	var u *url.URL
	var err error
	switch kind {
	case "sqlite":
		u, err = url.Parse("sqlite:" + dsn)
	case "postgres":
		u, err = url.Parse(dsn)
	default:
		return nil, fmt.Errorf("storage: unknown VAULT_STORAGE %q", kind)
	}
	if err != nil {
		return nil, fmt.Errorf("storage: bad dsn")
	}
	m := dbmate.New(u)
	m.FS = kdb.Migrations
	m.MigrationsDir = []string{"migrations/" + kind}
	m.AutoDumpSchema = false
	m.Log = discard{}
	return m, nil
}

// Migrate applies all pending migrations, creating the database if needed.
func Migrate(kind, dsn string) error {
	m, err := migrator(kind, dsn)
	if err != nil {
		return err
	}
	return m.CreateAndMigrate()
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func rebindDollar(q string) string {
	var b strings.Builder
	n := 0
	for _, r := range q {
		if r == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
