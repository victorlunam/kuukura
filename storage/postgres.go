package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

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

func (p *postgresProvider) TimeArg(t time.Time) any { return t.UTC() }

func (p *postgresProvider) LockAudit(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7266011)`)
	return err
}

func (p *postgresProvider) CheckAuditProtected(ctx context.Context, q Querier) error {
	var bad bool
	err := q.QueryRowContext(ctx, `SELECT has_table_privilege(current_user, 'audit_log', 'UPDATE')
		OR has_table_privilege(current_user, 'audit_log', 'DELETE') OR has_table_privilege(current_user, 'audit_log', 'TRUNCATE')`).Scan(&bad)
	if err != nil {
		return err
	}
	if bad {
		return errors.New("the database role can modify audit_log: connect as a login role that is a member of kuukura_app and does not own the tables")
	}
	return nil
}
