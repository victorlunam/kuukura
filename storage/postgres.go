package storage

import (
	"context"
	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type postgresProvider struct{ db *sql.DB }

func openPostgres(ctx context.Context, dsn string) (Provider, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &postgresProvider{db}, nil
}

func (p *postgresProvider) DB() *sql.DB            { return p.db }
func (p *postgresProvider) Rebind(q string) string { return rebindDollar(q) }
func (p *postgresProvider) TagsArg(t Tags) any     { return []string(append(Tags{}, t...)) }
func (p *postgresProvider) Close() error           { return p.db.Close() }

// Contains uses array containment, served by the GIN index.
func (p *postgresProvider) Contains(col string, sel Tags) (string, []any) {
	return col + " @> ?::text[]", []any{p.TagsArg(sel)}
}
