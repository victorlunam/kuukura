// Package secrets is the secrets domain: versions, revoke, archive, uniqueness, bulk changes.
package secrets

import (
	"context"
	"database/sql"
	"strings"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/access"
	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/keys"
	"github.com/victorlunam/kuukura/internal/storage"
)

// Error is the shared domain error (see access.Error).
type Error = access.Error

func fail(code, msg string, items ...string) *Error { return access.Fail(code, msg, items...) }

// conflict turns the loss of a race on a unique index (two writers creating or renaming to the same name and
// tags, or adding the same version) into a clash the caller can retry, instead of a database error.
func conflict(err error) error {
	if storage.IsUniqueViolation(err) {
		return fail(access.CodeClash, "changed at the same moment by someone else; try again")
	}
	return err
}

// Info is the listable view of a secret: never a value.
type Info struct {
	ID                uuid.UUID
	Name, Kind        string
	Version           int
	Tags              storage.Tags
	RequiresAuthorize bool
	Blocked           bool
}

// label is how a secret is named to people: "NAME tag tag".
func label(name string, tags []string) string {
	return strings.TrimSpace(name + " " + strings.Join(tags, " "))
}

func (i Info) label() string { return label(i.Name, i.Tags) }

type Service struct {
	p   storage.Provider
	kp  keys.KeyProvider
	log *audit.Log
}

func New(p storage.Provider, kp keys.KeyProvider, log *audit.Log) *Service {
	return &Service{p, kp, log}
}

func (s *Service) resolve(ctx context.Context, q storage.Querier, sel selector) ([]Info, error) {
	query := `SELECT s.id, s.name, s.kind, s.tags, s.requires_authorize, COALESCE(v.number, 0), COALESCE(v.compromised_at IS NOT NULL, false)
		FROM secrets s LEFT JOIN secret_versions v ON v.id = s.current_version_id
		WHERE s.archived_at IS NULL`
	var args []any
	if sel.name != "" {
		query += ` AND s.name = ?`
		args = append(args, sel.name)
	}
	cond, a := s.p.Contains("s.tags", sel.tags)
	query += ` AND ` + cond + ` ORDER BY s.name, s.tags, s.id`
	args = append(args, a...)
	rows, err := q.QueryContext(ctx, s.p.Rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Info
	for rows.Next() {
		var i Info
		if err := rows.Scan(&i.ID, &i.Name, &i.Kind, &i.Tags, &i.RequiresAuthorize, &i.Version, &i.Blocked); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// run executes fn in a transaction and records any denials after rollback.
func (s *Service) run(ctx context.Context, fn func(tx *sql.Tx, denied *[]audit.Entry) error) error {
	var denied []audit.Entry
	err := storage.InTx(ctx, s.p, func(tx *sql.Tx) error { return fn(tx, &denied) })
	for _, d := range denied {
		if rerr := s.log.Record(ctx, d); rerr != nil {
			return rerr
		}
	}
	return err
}

func deniedEntry(a access.Actor, action string, id uuid.UUID) audit.Entry {
	return audit.Entry{Principal: a.ID, Action: action, SecretID: &id, Result: audit.ResultDenied, IP: a.IP}
}

// readable resolves a selection and keeps the secrets the actor may read; unreadable ones are treated as absent.
// all is everything that matched, for callers that audit a denial.
func (s *Service) readable(ctx context.Context, tx storage.Querier, a access.Actor, sel selector) (all, rows []Info, err error) {
	if all, err = s.resolve(ctx, tx, sel); err != nil {
		return nil, nil, err
	}
	perm, err := access.For(ctx, s.p, tx, a, access.Read)
	if err != nil {
		return nil, nil, err
	}
	for _, r := range all {
		if perm.Allows(r.Tags) {
			rows = append(rows, r)
		}
	}
	return all, rows, nil
}

// List returns the secrets the actor can read (name, version, tags).
func (s *Service) List(ctx context.Context, a access.Actor, in Selector) ([]Info, error) {
	sel, err := in.parse()
	if err != nil {
		return nil, err
	}
	var out []Info
	err = s.run(ctx, func(tx *sql.Tx, _ *[]audit.Entry) error {
		var err error
		if _, out, err = s.readable(ctx, tx, a, sel); err != nil {
			return err
		}
		return s.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: "list", IP: a.IP, Metadata: map[string]any{"count": len(out)}})
	})
	return out, err
}

// writable is readable() plus a write check; readable-but-not-writable secrets deny.
func (s *Service) writable(ctx context.Context, tx *sql.Tx, a access.Actor, sel selector, action string, denied *[]audit.Entry) ([]Info, error) {
	_, rows, err := s.readable(ctx, tx, a, sel)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fail(access.CodeNotFound, "no matching secret")
	}
	perm, err := access.For(ctx, s.p, tx, a, access.Write)
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, r := range rows {
		if !perm.Allows(r.Tags) {
			bad = append(bad, r.label())
			*denied = append(*denied, deniedEntry(a, action, r.ID))
		}
	}
	if len(bad) > 0 {
		return nil, fail(access.CodeDenied, "not permitted", bad...)
	}
	return rows, nil
}
