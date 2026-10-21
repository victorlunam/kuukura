package audit

import (
	"context"
	"database/sql"
	"strings"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/storage"
)

const columns = `a.id, a.at, a.principal_id, a.action, a.secret_id, a.version, a.result, CAST(a.ip AS TEXT),
	a.target_type, a.target_id, CAST(a.metadata AS TEXT), a.prev_hash, a.hash`

func scanRow(rows *sql.Rows, extra ...any) (Row, error) {
	var r Row
	var at storage.Time
	var ip, tt, meta sql.NullString
	var ver sql.NullInt64
	var sid, tid uuid.NullUUID
	if err := rows.Scan(append([]any{&r.ID, &at, &r.Principal, &r.Action, &sid, &ver, &r.Result, &ip, &tt, &tid, &meta, &r.PrevHash, &r.Hash}, extra...)...); err != nil {
		return r, err
	}
	r.At = at.Time
	if sid.Valid {
		r.SecretID = &sid.UUID
	}
	if tid.Valid {
		r.TargetID = &tid.UUID
	}
	if ver.Valid {
		v := int(ver.Int64)
		r.Version = &v
	}
	if ip.Valid {
		host, _, _ := strings.Cut(ip.String, "/") // postgres inet renders as addr/len
		r.IP = host
	}
	r.TargetType = tt.String
	if meta.Valid {
		v, err := decodeJSON([]byte(meta.String))
		if err != nil {
			return r, err
		}
		m, _ := v.(map[string]any)
		r.Metadata = m
	}
	return r, nil
}

// Filter narrows List to rows about secrets with this name and/or tags.
type Filter struct {
	Name string
	Tags storage.Tags
	Not  storage.Tags
}

// Row counts of List: a limit outside 1..MaxLimit (including 0, "not given") means DefaultLimit.
const (
	DefaultLimit = 100
	MaxLimit     = 1000
)

// List returns rows newest first, with principal and secret names.
func (l *Log) List(ctx context.Context, f Filter, limit int) ([]Row, error) {
	if limit < 1 || limit > MaxLimit {
		limit = DefaultLimit
	}
	q := `SELECT ` + columns + `, COALESCE(pr.name, ''), COALESCE(s.name, '')
		FROM audit_log a LEFT JOIN principals pr ON pr.id = a.principal_id LEFT JOIN secrets s ON s.id = a.secret_id WHERE 1=1`
	var args []any
	if f.Name != "" {
		q += ` AND s.name = ?`
		args = append(args, strings.ToUpper(f.Name))
	}
	if len(f.Tags) > 0 {
		cond, a := l.p.Contains("s.tags", f.Tags)
		q += ` AND ` + cond
		args = append(args, a...)
	}
	if len(f.Not) > 0 {
		// Like Tags, this narrows to rows about secrets: a row with no secret has no tags column and drops out.
		cond, a := l.p.Excludes("s.tags", f.Not)
		q += ` AND ` + cond
		args = append(args, a...)
	}
	q += ` ORDER BY a.at DESC, a.id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := l.p.DB().QueryContext(ctx, l.p.Rebind(q), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var pn, sn string
		r, err := scanRow(rows, &pn, &sn)
		if err != nil {
			return nil, err
		}
		r.PrincipalName, r.SecretName = pn, sn
		out = append(out, r)
	}
	return out, rows.Err()
}

// Find returns the successful rows with this action and target type, newest first. It is for the few host-level
// events that have no secret behind them, such as a master key being shown.
func (l *Log) Find(ctx context.Context, action, targetType string) ([]Row, error) {
	rows, err := l.p.DB().QueryContext(ctx, l.p.Rebind(`SELECT `+columns+` FROM audit_log a
		WHERE a.action = ? AND a.target_type = ? AND a.result = 'ok' ORDER BY a.at DESC, a.id DESC`), action, targetType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
