// Package audit is the append-only, hash-chained audit log.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
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
