// Package storage is the pluggable database layer: sqlite or postgres.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

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
	// TimeArg encodes a time as a query argument for a timestamp column.
	TimeArg(t time.Time) any
	// CheckAuditProtected fails if the connected role could update or delete audit rows
	// (Postgres: the app must not own the tables; sqlite is protected by triggers).
	CheckAuditProtected(ctx context.Context, q Querier) error
	// LockAudit serializes audit appends for the rest of the transaction.
	LockAudit(ctx context.Context, tx *sql.Tx) error
	Close() error
}

// Querier is satisfied by *sql.DB and *sql.Tx. With sqlite (single connection)
// code inside a transaction must use the tx, never the DB.
type Querier interface {
	ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

// InTx runs fn in a transaction, committing on nil and rolling back on error.
func InTx(ctx context.Context, p Provider, fn func(tx *sql.Tx) error) error {
	tx, err := p.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Time scans a timestamp column from either dialect.
type Time struct{ time.Time }

func (t *Time) Scan(src any) error {
	switch v := src.(type) {
	case time.Time:
		t.Time = v.UTC()
	case string:
		pt, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return err
		}
		t.Time = pt.UTC()
	default:
		return fmt.Errorf("storage: cannot scan %T into Time", src)
	}
	return nil
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
