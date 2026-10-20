// Package audit is the append-only, hash-chained audit log.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/storage"
)

const (
	ResultOK     = "ok"
	ResultDenied = "denied"
	timeFormat   = "2006-01-02T15:04:05.000000Z"
)

// Entry is what a caller records. Metadata is context only, never values.
type Entry struct {
	Principal  uuid.UUID
	Action     string
	SecretID   *uuid.UUID
	Version    *int
	Result     string
	IP         string
	TargetType string
	TargetID   *uuid.UUID
	Metadata   map[string]any
}

// Row is a stored entry. PrincipalName and SecretName are filled by List only.
type Row struct {
	Entry
	PrincipalName string
	SecretName    string
	ID            uuid.UUID
	At            time.Time
	PrevHash      []byte
	Hash          []byte
}

type Log struct{ p storage.Provider }

func New(p storage.Provider) *Log { return &Log{p} }

var genesis = make([]byte, 32)

// Append adds an entry to the chain inside the caller's transaction.
func (l *Log) Append(ctx context.Context, tx *sql.Tx, e Entry) error {
	if e.Result == "" {
		e.Result = ResultOK
	}
	var ip, meta any
	if e.IP != "" {
		a, err := netip.ParseAddr(e.IP)
		if err != nil {
			return errors.New("audit: bad ip")
		}
		// The hash covers the stored form: Verify reads the canonical text back, so "FD00:0::1" must be hashed
		// as "fd00::1".
		e.IP = a.WithZone("").String()
		ip = e.IP
	}
	if err := l.p.LockAudit(ctx, tx); err != nil {
		return err
	}
	prev, prevAt, err := l.tip(ctx, tx)
	if err != nil {
		return err
	}
	// Strictly after the tip, even if the clock stepped back or two appends share a microsecond: the newest row by
	// time is then always the tip.
	at := time.Now().UTC().Truncate(time.Microsecond)
	if !at.After(prevAt) {
		at = prevAt.Add(time.Microsecond)
	}
	r := Row{Entry: e, ID: uuid.New(), At: at, PrevHash: prev}
	if r.Hash, err = r.computeHash(); err != nil {
		return err
	}
	if e.Metadata != nil {
		m, err := json.Marshal(e.Metadata)
		if err != nil {
			return err
		}
		meta = string(m)
	}
	_, err = tx.ExecContext(ctx, l.p.Rebind(`INSERT INTO audit_log
		(id, at, principal_id, action, secret_id, version, result, ip, target_type, target_id, metadata, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		r.ID, l.p.TimeArg(r.At), e.Principal, e.Action, e.SecretID, e.Version, e.Result, ip,
		nullStr(e.TargetType), e.TargetID, meta, prev, r.Hash)
	return err
}

// tip returns the hash and time of the last row of the chain (genesis if empty). The newest row by time is read
// through the (at, id) index; that is the tip unless it already has a successor, which only a hand-edited
// timestamp can cause, and then the anti-join finds the real one.
func (l *Log) tip(ctx context.Context, tx *sql.Tx) ([]byte, time.Time, error) {
	var hash []byte
	var at storage.Time
	err := tx.QueryRowContext(ctx, `SELECT hash, at FROM audit_log ORDER BY at DESC, id DESC LIMIT 1`).Scan(&hash, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return genesis, time.Time{}, nil
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	var successors int
	if err := tx.QueryRowContext(ctx, l.p.Rebind(`SELECT COUNT(*) FROM audit_log WHERE prev_hash = ?`), hash).Scan(&successors); err != nil {
		return nil, time.Time{}, err
	}
	if successors == 0 {
		return hash, at.Time, nil
	}
	err = tx.QueryRowContext(ctx, `SELECT a.hash, a.at FROM audit_log a
		WHERE NOT EXISTS (SELECT 1 FROM audit_log b WHERE b.prev_hash = a.hash)`).Scan(&hash, &at)
	return hash, at.Time, err
}

// Record appends one entry in its own transaction (used for denials).
func (l *Log) Record(ctx context.Context, e Entry) error {
	return storage.InTx(ctx, l.p, func(tx *sql.Tx) error { return l.Append(ctx, tx, e) })
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// computeHash = SHA-256(prev_hash || JCS(row without hash)).
func (r Row) computeHash() ([]byte, error) {
	opt := func(p *uuid.UUID) any {
		if p == nil {
			return nil
		}
		return p.String()
	}
	m := map[string]any{
		"id":           r.ID.String(),
		"at":           r.At.UTC().Format(timeFormat),
		"principal_id": r.Principal.String(),
		"action":       r.Action,
		"secret_id":    opt(r.SecretID),
		"version":      nil,
		"result":       r.Result,
		"ip":           nil,
		"target_type":  nil,
		"target_id":    opt(r.TargetID),
		"metadata":     nil,
		"prev_hash":    b64(r.PrevHash),
	}
	if r.Version != nil {
		m["version"] = *r.Version
	}
	if r.IP != "" {
		m["ip"] = r.IP
	}
	if r.TargetType != "" {
		m["target_type"] = r.TargetType
	}
	if r.Metadata != nil {
		// normalize through JSON so a stored-and-reloaded row hashes identically
		raw, _ := json.Marshal(r.Metadata)
		norm, err := decodeJSON(raw)
		if err != nil {
			return nil, err
		}
		m["metadata"] = norm
	}
	c, err := jcs(m)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(r.PrevHash)
	h.Write(c)
	return h.Sum(nil), nil
}

func decodeJSON(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	return v, d.Decode(&v)
}

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

// Head is the end of a verified chain. Keeping it somewhere else lets an operator notice a later truncation,
// which the chain alone cannot show.
type Head struct {
	Rows int
	Hash []byte
}

// Verify walks the chain from genesis and recomputes every hash.
func (l *Log) Verify(ctx context.Context) error {
	_, err := l.VerifyHead(ctx)
	return err
}

// VerifyHead is Verify that also returns the head of the chain.
func (l *Log) VerifyHead(ctx context.Context) (Head, error) {
	rows, err := l.p.DB().QueryContext(ctx, `SELECT `+columns+` FROM audit_log a`)
	if err != nil {
		return Head{}, err
	}
	defer rows.Close()
	byPrev := map[string]Row{}
	total := 0
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return Head{}, err
		}
		byPrev[string(r.PrevHash)] = r
		total++
	}
	if err := rows.Err(); err != nil {
		return Head{}, err
	}
	prev := genesis
	for n := 0; n < total; n++ {
		r, ok := byPrev[string(prev)]
		if !ok {
			return Head{}, fmt.Errorf("audit: chain broken after %d rows", n)
		}
		h, err := r.computeHash()
		if err != nil || !bytes.Equal(h, r.Hash) {
			return Head{}, fmt.Errorf("audit: row %s was altered", r.ID)
		}
		prev = r.Hash
	}
	return Head{Rows: total, Hash: prev}, nil
}

// Filter narrows List to rows about secrets with this name and/or tags.
type Filter struct {
	Name string
	Tags storage.Tags
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
