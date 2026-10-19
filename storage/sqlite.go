package storage

import (
	"context"
	"database/sql"
	"net/url"
	"strings"

	_ "modernc.org/sqlite"
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
