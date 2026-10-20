package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

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
