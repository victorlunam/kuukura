package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/storage"
)

// Methods are the second steps an account has set up. Default is the kind of its default factor ("" if none),
// the one the pages offer first.
type Methods struct {
	Passkey, TOTP bool
	Default       string
}

func (s *Service) factorsOf(ctx context.Context, q storage.Querier, principal uuid.UUID) (m Methods, err error) {
	rows, err := q.QueryContext(ctx, s.p.Rebind(`SELECT kind, is_default FROM credentials WHERE principal_id = ?`), principal)
	if err != nil {
		return m, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var def bool
		if err := rows.Scan(&kind, &def); err != nil {
			return m, err
		}
		m.Passkey = m.Passkey || kind == "passkey"
		m.TOTP = m.TOTP || kind == "totp"
		if def {
			m.Default = kind
		}
	}
	return m, rows.Err()
}

// EnrollResult is shown once: the login redirect and, on first enrollment, the recovery codes.
type EnrollResult struct {
	Redirect      string
	RecoveryCodes []string
}

// activate stores a new factor. During first enrollment it also activates the invited principal, issues recovery
// codes once and finishes the login. When add is set the account is already active: it only stores the factor,
// ends the short enroll session and audits the change (no login, no new recovery codes).
func (s *Service) activate(ctx context.Context, in Info, ip, add string, addFactor func(*sql.Tx) error) (EnrollResult, error) {
	if add != "" {
		err := storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
			if err := addFactor(tx); err != nil {
				return err
			}
			if err := s.tokens.Revoke(ctx, tx, in.TokenID); err != nil {
				return err
			}
			pid := in.PrincipalID
			return s.log.Append(ctx, tx, audit.Entry{Principal: pid, Action: "update", IP: ip, TargetType: "principal", TargetID: &pid,
				Metadata: map[string]any{"factor": add, "change": "added"}})
		})
		s.pending.Take(in.TokenID.String())
		return EnrollResult{Redirect: "/account/added"}, err
	}
	var res EnrollResult
	err := storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		if err := addFactor(tx); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE principals SET status = 'active' WHERE id = ? AND status = 'invited'`), in.PrincipalID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT COUNT(*) FROM recovery_codes WHERE principal_id = ?`), in.PrincipalID).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			var err error
			if res.RecoveryCodes, err = s.newRecoveryCodes(ctx, tx, in.PrincipalID); err != nil {
				return err
			}
		}
		var err error
		res.Redirect, err = s.finish(ctx, tx, in, ip)
		return err
	})
	return res, err
}

// ---- managing the second factors of an active account ----

// ErrLastFactor: removing it would leave the account with no second step.
var ErrLastFactor = errors.New("auth: last second factor")

// ErrNoSuchFactor: the id is not a factor of this account (the same answer for someone else's).
var ErrNoSuchFactor = errors.New("auth: no such factor")

const addFactorTTL = 10 * time.Minute

// Factor is one second step of the caller's account. Added is the date (YYYY-MM-DD).
type Factor struct {
	ID      uuid.UUID
	Kind    string
	Added   string
	Default bool
}

// ListFactors returns the caller's second factors, oldest first.
func (s *Service) ListFactors(ctx context.Context, in Info) ([]Factor, error) {
	rows, err := s.p.DB().QueryContext(ctx, s.p.Rebind(`SELECT id, kind, CAST(created_at AS TEXT), is_default FROM credentials WHERE principal_id = ? ORDER BY created_at, id`), in.PrincipalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Factor
	for rows.Next() {
		var f Factor
		var at string
		if err := rows.Scan(&f.ID, &f.Kind, &at, &f.Default); err != nil {
			return nil, err
		}
		f.Added = at[:min(10, len(at))]
		out = append(out, f)
	}
	return out, rows.Err()
}

type addReq struct {
	principal uuid.UUID
	kind      string
}

// StartAddFactor returns the one-time capability behind the page link that adds a passkey or an authenticator
// app to the caller's account. The API checks the confirmation before calling it. Machines have no factors.
func (s *Service) StartAddFactor(in Info, kind string) (string, error) {
	if in.Machine || kind != "passkey" && kind != "totp" {
		return "", ErrLogin
	}
	id := random(32)
	s.adds.Put(id, addReq{in.PrincipalID, kind})
	return id, nil
}

// OpenAddFactor spends the link and issues a short enroll session for that one kind of factor. The account
// is already active, so the session ends after the factor is stored: no login, no new recovery codes.
func (s *Service) OpenAddFactor(ctx context.Context, id string) (Pending, error) {
	r, ok := s.adds.Take(id)
	if !ok {
		return Pending{}, ErrLogin
	}
	var out Pending
	err := storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		var status string
		if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT status FROM principals WHERE id = ?`), r.principal).Scan(&status); err != nil || status != "active" {
			return ErrLogin
		}
		iss, err := s.tokens.Issue(ctx, tx, r.principal, KindSession, []string{ScopeEnroll}, pendingEnrollTTL)
		if err != nil {
			return err
		}
		out = Pending{Token: iss.Raw, PrincipalID: r.principal, Mode: "add", Add: r.kind}
		s.pending.Put(iss.ID.String(), pendingData{add: r.kind})
		return nil
	})
	return out, err
}

// RemoveFactor deletes one of the caller's factors; the last one stays.
func (s *Service) RemoveFactor(ctx context.Context, in Info, id uuid.UUID, ip string) error {
	if in.Machine {
		return ErrLogin
	}
	return storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		var kind string
		if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT kind FROM credentials WHERE id = ? AND principal_id = ?`), id, in.PrincipalID).Scan(&kind); errors.Is(err, sql.ErrNoRows) {
			return ErrNoSuchFactor
		} else if err != nil {
			return err
		}
		var n int
		if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT COUNT(*) FROM credentials WHERE principal_id = ?`), in.PrincipalID).Scan(&n); err != nil {
			return err
		}
		if n <= 1 {
			return ErrLastFactor
		}
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`DELETE FROM credentials WHERE id = ? AND principal_id = ?`), id, in.PrincipalID); err != nil {
			return err
		}
		// if the default went away, the oldest remaining factor takes over
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE credentials SET is_default = ? WHERE id = (SELECT id FROM credentials WHERE principal_id = ? ORDER BY created_at, id LIMIT 1)
			AND NOT EXISTS (SELECT 1 FROM credentials WHERE principal_id = ? AND is_default = ?)`), true, in.PrincipalID, in.PrincipalID, true); err != nil {
			return err
		}
		pid := in.PrincipalID
		return s.log.Append(ctx, tx, audit.Entry{Principal: pid, Action: "update", IP: ip, TargetType: "principal", TargetID: &pid,
			Metadata: map[string]any{"factor": kind, "change": "removed"}})
	})
}

// SetDefaultFactor makes one of the caller's factors the default: the one the sign-in and confirmation pages
// offer first. Every factor keeps working; this only decides the order.
func (s *Service) SetDefaultFactor(ctx context.Context, in Info, id uuid.UUID, ip string) error {
	if in.Machine {
		return ErrLogin
	}
	return storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		var kind string
		if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT kind FROM credentials WHERE id = ? AND principal_id = ?`), id, in.PrincipalID).Scan(&kind); errors.Is(err, sql.ErrNoRows) {
			return ErrNoSuchFactor
		} else if err != nil {
			return err
		}
		// two statements: the unique index allows one default at a time
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE credentials SET is_default = ? WHERE principal_id = ?`), false, in.PrincipalID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE credentials SET is_default = ? WHERE id = ?`), true, id); err != nil {
			return err
		}
		pid := in.PrincipalID
		return s.log.Append(ctx, tx, audit.Entry{Principal: pid, Action: "update", IP: ip, TargetType: "principal", TargetID: &pid,
			Metadata: map[string]any{"factor": kind, "change": "default"}})
	})
}
