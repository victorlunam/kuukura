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

	"github.com/victorlunam/kuukura/storage"
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

// Row is a stored entry.
type Row struct {
	Entry
	ID       uuid.UUID
	At       time.Time
	PrevHash []byte
	Hash     []byte
}

type Log struct{ p storage.Provider }

func New(p storage.Provider) *Log { return &Log{p} }

var genesis = make([]byte, 32)

// Append adds an entry to the chain inside the caller's transaction.
func (l *Log) Append(ctx context.Context, tx *sql.Tx, e Entry) error {
	if e.Result == "" {
		e.Result = ResultOK
	}
	if err := l.p.LockAudit(ctx, tx); err != nil {
		return err
	}
	prev := genesis
	err := tx.QueryRowContext(ctx, `SELECT hash FROM audit_log a
		WHERE NOT EXISTS (SELECT 1 FROM audit_log b WHERE b.prev_hash = a.hash)`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		prev = genesis
	}
	r := Row{Entry: e, ID: uuid.New(), At: time.Now().UTC().Truncate(time.Microsecond), PrevHash: prev}
	if r.Hash, err = r.computeHash(); err != nil {
		return err
	}
	var ip, meta any
	if e.IP != "" {
		a, err := netip.ParseAddr(e.IP)
		if err != nil {
			return errors.New("audit: bad ip")
		}
		ip = a.String()
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

const selectRow = `SELECT a.id, a.at, a.principal_id, a.action, a.secret_id, a.version, a.result, CAST(a.ip AS TEXT),
	a.target_type, a.target_id, CAST(a.metadata AS TEXT), a.prev_hash, a.hash FROM audit_log a`

func scanRow(rows *sql.Rows) (Row, error) {
	var r Row
	var at storage.Time
	var ip, tt, meta sql.NullString
	var ver sql.NullInt64
	var sid, tid uuid.NullUUID
	if err := rows.Scan(&r.ID, &at, &r.Principal, &r.Action, &sid, &ver, &r.Result, &ip, &tt, &tid, &meta, &r.PrevHash, &r.Hash); err != nil {
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

// Verify walks the chain from genesis and recomputes every hash.
func (l *Log) Verify(ctx context.Context) error {
	rows, err := l.p.DB().QueryContext(ctx, selectRow)
	if err != nil {
		return err
	}
	defer rows.Close()
	byPrev := map[string]Row{}
	total := 0
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return err
		}
		byPrev[string(r.PrevHash)] = r
		total++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	prev := genesis
	for n := 0; n < total; n++ {
		r, ok := byPrev[string(prev)]
		if !ok {
			return fmt.Errorf("audit: chain broken after %d rows", n)
		}
		h, err := r.computeHash()
		if err != nil || !bytes.Equal(h, r.Hash) {
			return fmt.Errorf("audit: row %s was altered", r.ID)
		}
		prev = r.Hash
	}
	return nil
}

// Filter narrows List to rows about secrets with this name and/or tags.
type Filter struct {
	Name string
	Tags storage.Tags
}

// List returns rows newest first.
func (l *Log) List(ctx context.Context, f Filter, limit int) ([]Row, error) {
	q := selectRow
	var args []any
	if f.Name != "" || len(f.Tags) > 0 {
		q += ` JOIN secrets s ON s.id = a.secret_id WHERE 1=1`
		if f.Name != "" {
			q += ` AND s.name = ?`
			args = append(args, strings.ToUpper(f.Name))
		}
		cond, a := l.p.Contains("s.tags", f.Tags)
		q += ` AND ` + cond
		args = append(args, a...)
	}
	q += ` ORDER BY a.at DESC, a.id LIMIT ?`
	args = append(args, limit)
	rows, err := l.p.DB().QueryContext(ctx, l.p.Rebind(q), args...)
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
