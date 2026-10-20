// Package auth holds tokens, sessions, second factors and the login flows.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/storage"
)

const (
	KindSession    = "session"
	KindMachineKey = "machine_key"
	KindInvite     = "invite"

	SessionTTL     = 8 * time.Hour
	IdleTimeout    = time.Hour
	MachineKeyTTL  = 90 * 24 * time.Hour
	InviteTTL      = 24 * time.Hour
	AdminInviteTTL = 15 * time.Minute

	// Scopes. A session with only "mfa" or "enroll" is mid-login and unusable for the API.
	ScopeRead   = "read"
	ScopeWrite  = "write"
	ScopeMFA    = "mfa"
	ScopeEnroll = "enroll"

	prefix = "ku_"
)

// ErrInvalid is the one error for every bad token: unknown, expired, revoked, idle, disabled.
var ErrInvalid = errors.New("auth: invalid token")

type Tokens struct {
	p   storage.Provider
	Now func() time.Time
}

func NewTokens(p storage.Provider) *Tokens { return &Tokens{p: p, Now: time.Now} }

// Issued is returned once; only the hash is stored.
type Issued struct {
	Raw       string
	ID        uuid.UUID
	ExpiresAt time.Time
}

func hash(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

// Issue creates a token for a principal inside the caller's transaction.
func (t *Tokens) Issue(ctx context.Context, q storage.Querier, principal uuid.UUID, kind string, scopes []string, ttl time.Duration) (Issued, error) {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails: crypto/rand crashes the program instead
	raw := prefix + base64.RawURLEncoding.EncodeToString(b)
	id := uuid.New()
	exp := t.Now().UTC().Add(ttl)
	_, err := q.ExecContext(ctx, t.p.Rebind(`INSERT INTO tokens (id, principal_id, kind, scopes, token_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?)`),
		id, principal, kind, t.p.TagsArg(scopes), hash(raw), t.p.TimeArg(exp))
	return Issued{raw, id, exp}, err
}

// Info describes a valid token and its principal.
type Info struct {
	TokenID     uuid.UUID
	PrincipalID uuid.UUID
	Kind        string
	Scopes      []string
	Machine     bool
	Role        string
	Status      string
}

func (i Info) HasScope(s string) bool { return slices.Contains(i.Scopes, s) }

type tokenRow struct {
	Info
	hash            []byte
	expires, create storage.Time
	lastUsed        *storage.Time
	revoked         *storage.Time
	pkind           string
}

func (t *Tokens) lookup(ctx context.Context, q storage.Querier, raw string) (tokenRow, error) {
	var r tokenRow
	var role sql.NullString
	var scopes storage.Tags
	err := q.QueryRowContext(ctx, t.p.Rebind(`SELECT t.id, t.principal_id, t.kind, t.scopes, t.token_hash, t.expires_at, t.created_at, t.last_used_at, t.revoked_at,
		p.kind, p.role, p.status FROM tokens t JOIN principals p ON p.id = t.principal_id WHERE t.token_hash = ?`), hash(raw)).
		Scan(&r.TokenID, &r.PrincipalID, &r.Kind, &scopes, &r.hash, &r.expires, &r.create, &r.lastUsed, &r.revoked, &r.pkind, &role, &r.Status)
	if err != nil {
		return r, ErrInvalid
	}
	r.Scopes = scopes
	r.Role = role.String
	r.Machine = r.pkind == "machine"
	if subtle.ConstantTimeCompare(r.hash, hash(raw)) != 1 {
		return r, ErrInvalid
	}
	return r, nil
}

// Validate authenticates a bearer token and records its use. Invite tokens never validate here.
func (t *Tokens) Validate(ctx context.Context, raw string) (Info, error) {
	if !strings.HasPrefix(raw, prefix) {
		return Info{}, ErrInvalid
	}
	r, err := t.lookup(ctx, t.p.DB(), raw)
	if err != nil {
		return Info{}, err
	}
	now := t.Now().UTC()
	switch {
	case r.Kind == KindInvite, r.revoked != nil, !now.Before(r.expires.Time):
		return Info{}, ErrInvalid
	case r.Status == "disabled", r.Status == "invited" && !slices.Contains(r.Scopes, ScopeEnroll):
		return Info{}, ErrInvalid
	case r.Kind == KindSession:
		last := r.create.Time
		if r.lastUsed != nil {
			last = r.lastUsed.Time
		}
		if now.Sub(last) > IdleTimeout {
			return Info{}, ErrInvalid
		}
	}
	if _, err := t.p.DB().ExecContext(ctx, t.p.Rebind(`UPDATE tokens SET last_used_at = ? WHERE id = ?`), t.p.TimeArg(now), r.TokenID); err != nil {
		return Info{}, err
	}
	return r.Info, nil
}

// ConsumeInvite validates an invite token and invalidates it (single use).
// It returns the invited principal.
func (t *Tokens) ConsumeInvite(ctx context.Context, q storage.Querier, raw string) (uuid.UUID, error) {
	if !strings.HasPrefix(raw, prefix) {
		return uuid.Nil, ErrInvalid
	}
	r, err := t.lookup(ctx, q, raw)
	now := t.Now().UTC()
	if err != nil || r.Kind != KindInvite || r.revoked != nil || !now.Before(r.expires.Time) || r.Status == "disabled" {
		return uuid.Nil, ErrInvalid
	}
	res, err := q.ExecContext(ctx, t.p.Rebind(`UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`), t.p.TimeArg(now), r.TokenID)
	if err != nil {
		return uuid.Nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return uuid.Nil, ErrInvalid
	}
	return r.PrincipalID, nil
}

// PeekInvite checks an invite without consuming it and returns its principal's email.
func (t *Tokens) PeekInvite(ctx context.Context, raw string) (email string, err error) {
	if !strings.HasPrefix(raw, prefix) {
		return "", ErrInvalid
	}
	r, err := t.lookup(ctx, t.p.DB(), raw)
	if err != nil || r.Kind != KindInvite || r.revoked != nil || !t.Now().UTC().Before(r.expires.Time) {
		return "", ErrInvalid
	}
	var e sql.NullString
	if err := t.p.DB().QueryRowContext(ctx, t.p.Rebind(`SELECT email FROM principals WHERE id = ?`), r.PrincipalID).Scan(&e); err != nil {
		return "", ErrInvalid
	}
	return e.String, nil
}

// Revoke invalidates one token.
func (t *Tokens) Revoke(ctx context.Context, q storage.Querier, id uuid.UUID) error {
	_, err := q.ExecContext(ctx, t.p.Rebind(`UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`), t.p.TimeArg(t.Now()), id)
	return err
}

// RevokeAll ends every live token of a principal and returns how many.
func (t *Tokens) RevokeAll(ctx context.Context, q storage.Querier, principal uuid.UUID) (int64, error) {
	res, err := q.ExecContext(ctx, t.p.Rebind(`UPDATE tokens SET revoked_at = ? WHERE principal_id = ? AND revoked_at IS NULL`), t.p.TimeArg(t.Now()), principal)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
