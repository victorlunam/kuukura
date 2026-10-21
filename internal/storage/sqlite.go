package storage

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

type sqliteProvider struct{ db *sql.DB }

func openSQLite(ctx context.Context, path string) (Provider, error) {
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // single writer
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &sqliteProvider{db}, nil
}

func (p *sqliteProvider) DB() *sql.DB            { return p.db }
func (p *sqliteProvider) Rebind(q string) string { return q }
func (p *sqliteProvider) TagsArg(t Tags) any     { return sqliteTags(t) }
func (p *sqliteProvider) Close() error           { return p.db.Close() }

func (p *sqliteProvider) Contains(col string, sel Tags) (string, []any) {
	if len(sel) == 0 {
		return "1=1", nil
	}
	conds := make([]string, len(sel))
	args := make([]any, len(sel))
	for i, t := range sel {
		conds[i] = "instr(" + col + ", ?) > 0"
		args[i] = "," + t + ","
	}
	return "(" + strings.Join(conds, " AND ") + ")", args
}

func (p *sqliteProvider) Excludes(col string, sel Tags) (string, []any) {
	if len(sel) == 0 {
		return "1=1", nil
	}
	conds := make([]string, len(sel))
	args := make([]any, len(sel))
	for i, t := range sel {
		conds[i] = "instr(" + col + ", ?) = 0"
		args[i] = "," + t + ","
	}
	return "(" + strings.Join(conds, " AND ") + ")", args
}

// TimeArg is fixed width (microseconds), so text order is time order among values written through it. Columns
// that fall back to their DEFAULT hold whole seconds ("...:05Z", written by strftime), which are not that width:
// two of them tie within a second, and one sorts after a microsecond value of the same second ('Z' > '.').
// Changing the default would need a table rebuild in SQLite, so code that orders such a column adds a tie-break.
func (p *sqliteProvider) TimeArg(t time.Time) any {
	return t.UTC().Format("2006-01-02T15:04:05.000000Z")
}

// ForUpdate is empty: the single connection already serializes transactions.
func (p *sqliteProvider) ForUpdate() string { return "" }

func sqliteUnique(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	c := se.Code()
	return c == sqlite3.SQLITE_CONSTRAINT_UNIQUE || c == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
}

// LockAudit is a no-op: sqlite has a single connection, so transactions are serial.
func (p *sqliteProvider) LockAudit(context.Context, *sql.Tx) error { return nil }

func (p *sqliteProvider) CheckAuditProtected(context.Context, Querier) error { return nil }
