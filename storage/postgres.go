package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
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

func (p *postgresProvider) ForUpdate() string { return " FOR UPDATE" }

func pgUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func (p *postgresProvider) LockAudit(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7266011)`)
	return err
}

// CheckAuditProtected refuses a role that can modify audit_log, and one that is (or can become, through
// membership, even without inheriting its privileges) the table owner: an owner can re-grant itself anything.
func (p *postgresProvider) CheckAuditProtected(ctx context.Context, q Querier) error {
	var canModify, ownerOrMember bool
	err := q.QueryRowContext(ctx, `SELECT
		has_table_privilege(current_user, 'audit_log', 'UPDATE') OR has_table_privilege(current_user, 'audit_log', 'DELETE')
			OR has_table_privilege(current_user, 'audit_log', 'TRUNCATE'),
		pg_has_role(current_user, (SELECT relowner FROM pg_class WHERE oid = 'audit_log'::regclass), 'MEMBER')`).Scan(&canModify, &ownerOrMember)
	if err != nil {
		return err
	}
	if canModify {
		return errors.New("the database role can modify audit_log: connect as a login role that is a member of kuukura_app and is not the table owner")
	}
	if ownerOrMember {
		return errors.New("the database role owns audit_log or is a member of its owner: connect as a login role that is a member of kuukura_app only")
	}
	return nil
}
