package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/victorlunam/kuukura/internal/keys"
	"github.com/victorlunam/kuukura/internal/storage"
)

// ---- TOTP secrets are stored encrypted under the master key ----

func totpAAD(principal uuid.UUID) []byte { return append([]byte("kuukura-totp\x00"), principal[:]...) }

// sealTOTP encodes as len(key_id) u8 || key_id || wrapped.
func (s *Service) sealTOTP(ctx context.Context, principal uuid.UUID, secret string) ([]byte, error) {
	w, err := s.kp.Wrap(ctx, []byte(secret), totpAAD(principal))
	if err != nil {
		return nil, err
	}
	id := s.kp.KeyID()
	return append(append([]byte{byte(len(id))}, id...), w...), nil // #nosec G115 -- key ids are short
}

func (s *Service) openTOTP(ctx context.Context, principal uuid.UUID, b []byte) (string, error) {
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return "", ErrLogin
	}
	n := int(b[0])
	pt, err := s.kp.Unwrap(ctx, string(b[1:1+n]), b[1+n:], totpAAD(principal))
	return string(pt), err
}

var totpOpts = totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}

// totpStep returns the 30-second step a code belongs to if it is valid within +-1 step of now (RFC 6238).
func totpStep(secret, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	for _, off := range []time.Duration{0, -30 * time.Second, 30 * time.Second} {
		t := now.UTC().Add(off)
		want, err := totp.GenerateCodeCustom(secret, t, totpOpts)
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return t.Unix() / 30, true
		}
	}
	return 0, false
}

// consumeTOTP checks a code against the principal's authenticator apps and spends it: a code (really its 30 s
// step) works once, across login and confirmations alike, so a code seen over a shoulder or in a log is useless.
func (s *Service) consumeTOTP(ctx context.Context, principal uuid.UUID, code string) (bool, error) {
	rows, err := s.p.DB().QueryContext(ctx, s.p.Rebind(`SELECT id, encrypted_totp_secret FROM credentials WHERE principal_id = ? AND kind = 'totp'`), principal)
	if err != nil {
		return false, err
	}
	type cred struct {
		id  uuid.UUID
		enc []byte
	}
	var creds []cred
	for rows.Next() {
		var c cred
		if err := rows.Scan(&c.id, &c.enc); err != nil {
			_ = rows.Close()
			return false, err
		}
		creds = append(creds, c)
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	for _, c := range creds {
		secret, err := s.openTOTP(ctx, principal, c.enc)
		if err != nil { // a key outage must not look like a wrong code
			return false, fmt.Errorf("auth: open authenticator secret: %w", err)
		}
		step, ok := totpStep(secret, code, s.now())
		if !ok {
			continue
		}
		at := s.p.TimeArg(time.Unix(step*30, 0).UTC())
		res, err := s.p.DB().ExecContext(ctx, s.p.Rebind(`UPDATE credentials SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)`), at, c.id, at)
		if err != nil {
			return false, err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return true, nil
		}
		// a valid code, but that step was already used
	}
	return false, nil
}

// VerifyTOTP checks a 6-digit code and completes the login.
func (s *Service) VerifyTOTP(ctx context.Context, in Info, code, ip string) (string, error) {
	if _, err := s.requireScope(in, ScopeMFA); err != nil {
		return "", err
	}
	ok, err := s.consumeTOTP(ctx, in.PrincipalID, code)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", s.failed(ctx, in, ip)
	}
	var redirect string
	err = storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		var err error
		redirect, err = s.finish(ctx, tx, in, ip)
		return err
	})
	return redirect, err
}

// BeginTOTP generates a secret for the enroll session; it is stored only after a valid code confirms it.
func (s *Service) BeginTOTP(ctx context.Context, in Info) (secret, uri string, err error) {
	d, err := s.requireScope(in, ScopeEnroll)
	if err != nil || d.add != "" && d.add != "totp" { // an "add a passkey" session cannot register an app
		return "", "", ErrLogin
	}
	u, _, err := s.loadUser(ctx, in.PrincipalID)
	if err != nil {
		return "", "", err
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.cfg.Issuer, AccountName: u.name, Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		return "", "", err
	}
	s.pending.Update(in.TokenID.String(), func(d *pendingData) { d.totpSecret = key.Secret() })
	return key.Secret(), key.URL(), nil
}

// ConfirmTOTP verifies the first code, stores the encrypted secret, activates and completes the login. The
// code's step is stored as used, so the enrollment code cannot be replayed at the next sign-in.
func (s *Service) ConfirmTOTP(ctx context.Context, in Info, code, ip string) (EnrollResult, error) {
	d, err := s.requireScope(in, ScopeEnroll)
	if err != nil || d.totpSecret == "" || d.add != "" && d.add != "totp" {
		return EnrollResult{}, ErrLogin
	}
	step, ok := totpStep(d.totpSecret, code, s.now())
	if !ok {
		return EnrollResult{}, ErrLogin
	}
	enc, err := s.sealTOTP(ctx, in.PrincipalID, d.totpSecret)
	if err != nil {
		return EnrollResult{}, err
	}
	return s.activate(ctx, in, ip, d.add, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, s.p.Rebind(`INSERT INTO credentials (id, principal_id, kind, encrypted_totp_secret, last_used_at, is_default)
			VALUES (?, ?, 'totp', ?, ?, NOT EXISTS (SELECT 1 FROM credentials WHERE principal_id = ?))`),
			uuid.New(), in.PrincipalID, enc, s.p.TimeArg(time.Unix(step*30, 0).UTC()), in.PrincipalID)
		return err
	})
}

// RewrapTOTP moves stored TOTP secrets to the provider's active key. Returns how many were rewrapped.
func (s *Service) RewrapTOTP(ctx context.Context) (int, error) {
	n := 0
	err := storage.InTx(ctx, s.p, func(tx *sql.Tx) (err error) {
		n, err = s.RewrapTOTPTx(ctx, tx)
		return err
	})
	return n, err
}

// RewrapTOTPTx is RewrapTOTP inside the caller's transaction, so a rotation can commit all its work together.
func (s *Service) RewrapTOTPTx(ctx context.Context, tx *sql.Tx) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, principal_id, encrypted_totp_secret FROM credentials WHERE kind = 'totp'`)
	if err != nil {
		return 0, err
	}
	type item struct {
		id, principal uuid.UUID
		enc           []byte
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.principal, &it.enc); err != nil {
			_ = rows.Close()
			return 0, err
		}
		items = append(items, it)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	n := 0
	for _, it := range items {
		if len(it.enc) > 0 && int(it.enc[0]) < len(it.enc) && string(it.enc[1:1+int(it.enc[0])]) == s.kp.KeyID() {
			continue
		}
		secret, err := s.openTOTP(ctx, it.principal, it.enc)
		if err != nil {
			return 0, err
		}
		enc, err := s.sealTOTP(ctx, it.principal, secret)
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE credentials SET encrypted_totp_secret = ? WHERE id = ?`), enc, it.id); err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}

// HasTOTP reports whether any authenticator-app secret is stored (encrypted under the master key).
func (s *Service) HasTOTP(ctx context.Context) (bool, error) {
	var n int
	err := s.p.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM credentials WHERE kind = 'totp'`).Scan(&n)
	return n > 0, err
}

// CheckKey opens one stored authenticator secret with the master key, so a wrong key is found at start instead of
// at somebody's login. It passes when there is none.
func (s *Service) CheckKey(ctx context.Context) error {
	var principal uuid.UUID
	var enc []byte
	err := s.p.DB().QueryRowContext(ctx, `SELECT principal_id, encrypted_totp_secret FROM credentials WHERE kind = 'totp' LIMIT 1`).Scan(&principal, &enc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := s.openTOTP(ctx, principal, enc); err != nil {
		if errors.Is(err, keys.ErrDecrypt) || errors.Is(err, ErrLogin) {
			return keys.MismatchError(storedKeyID(enc))
		}
		return err
	}
	return nil
}

// storedKeyID is the key id a sealed TOTP secret names (see sealTOTP).
func storedKeyID(enc []byte) string {
	if len(enc) < 1 || len(enc) < 1+int(enc[0]) {
		return "unknown"
	}
	return string(enc[1 : 1+int(enc[0])])
}
