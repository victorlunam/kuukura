// Package storage is the pluggable database layer: sqlite or postgres.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
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
	// ForUpdate is appended to a SELECT to lock the rows it returns until the transaction ends (empty on sqlite,
	// which has one connection and no such syntax).
	ForUpdate() string
	Close() error
}

// IsUniqueViolation reports whether err is a unique-constraint failure, on either backend.
func IsUniqueViolation(err error) bool { return pgUnique(err) || sqliteUnique(err) }

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
