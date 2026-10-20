package identity

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/access"
	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/auth"
	"github.com/victorlunam/kuukura/storage"
)

// HostName is the principal that every action taken on the server's host is audited under (ku-server user
// invite, key rotate, ...). It is a disabled machine with no owner: it can never sign in or hold a token, and it
// is hidden from ListPeople and from every name lookup.
const HostName = "ku-server"

func (s *Service) hostID(ctx context.Context, q storage.Querier) (uuid.UUID, error) {
	sel := s.p.Rebind(`SELECT id FROM principals WHERE name = ? AND kind = 'machine' AND owner_id IS NULL`)
	var id uuid.UUID
	err := q.QueryRowContext(ctx, sel, HostName).Scan(&id)
	if !errors.Is(err, sql.ErrNoRows) {
		return id, err
	}
	if _, err := q.ExecContext(ctx, s.p.Rebind(`INSERT INTO principals (id, kind, name, status) VALUES (?, 'machine', ?, 'disabled') ON CONFLICT (name) DO NOTHING`), uuid.New(), HostName); err != nil {
		return id, err
	}
	return id, q.QueryRowContext(ctx, sel, HostName).Scan(&id)
}

// HostPrincipal returns the id of the host principal, creating it on first use.
func (s *Service) HostPrincipal(ctx context.Context) (uuid.UUID, error) {
	return s.hostID(ctx, s.p.DB())
}

// hostTx runs fn in a transaction with the host principal as its actor.
func (s *Service) hostTx(ctx context.Context, fn func(tx *sql.Tx, host uuid.UUID) error) error {
	host, err := s.HostPrincipal(ctx)
	if err != nil {
		return err
	}
	return storage.InTx(ctx, s.p, func(tx *sql.Tx) error { return fn(tx, host) })
}

// Person is one row of ListPeople.
type Person struct {
	Name    string // the email of a person, the name of a machine
	Kind    string
	Role    string // "" for machines
	Status  string
	Factors int // passkeys and authenticator apps
	Created time.Time
}

// ListPeople returns every person and machine except the host principal.
func (s *Service) ListPeople(ctx context.Context) ([]Person, error) {
	rows, err := s.p.DB().QueryContext(ctx, s.p.Rebind(`SELECT p.name, p.kind, COALESCE(p.role, ''), p.status, p.created_at,
		(SELECT COUNT(*) FROM credentials c WHERE c.principal_id = p.id)
		FROM principals p WHERE p.name <> ? ORDER BY p.kind, p.name`), HostName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Person
	for rows.Next() {
		var p Person
		var at storage.Time
		if err := rows.Scan(&p.Name, &p.Kind, &p.Role, &p.Status, &at, &p.Factors); err != nil {
			return nil, err
		}
		p.Created = at.Time
		out = append(out, p)
	}
	return out, rows.Err()
}

// InviteByHost is the server-side invite (15 min): it creates the person, or issues a fresh link to one who has
// not signed in yet. A person who is already enrolled needs ResetFactorsByHost. The link is never audited.
func (s *Service) InviteByHost(ctx context.Context, email string, admin bool) (Invite, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !emailRE.MatchString(email) {
		return Invite{}, access.Fail(access.CodeInvalid, "invalid email")
	}
	role := "member"
	if admin {
		role = "admin"
	}
	var inv Invite
	err := s.hostTx(ctx, func(tx *sql.Tx, host uuid.UUID) error {
		var id uuid.UUID
		var cur, status sql.NullString
		err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT id, role, status FROM principals WHERE name = ?`), email).Scan(&id, &cur, &status)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if id, err = s.createHuman(ctx, tx, email, role); err != nil {
				return err
			}
		case err != nil:
			return err
		case cur.String != role:
			return access.Fail(access.CodeConflict, "that person exists as a "+cur.String+", not a "+role)
		case status.String != "invited":
			return access.Fail(access.CodeConflict, "that person is already enrolled: use `ku-server user reset-factors` if they lost their passkey and recovery codes")
		}
		iss, err := s.tokens.Issue(ctx, tx, id, auth.KindInvite, nil, auth.AdminInviteTTL)
		if err != nil {
			return err
		}
		inv = Invite{iss.Raw, iss.ExpiresAt}
		return s.log.Append(ctx, tx, audit.Entry{Principal: host, Action: "invite", TargetType: "principal", TargetID: &id,
			Metadata: map[string]any{"kind": "human", "role": role, "via": "host"}})
	})
	return inv, err
}

// DisableByHost is Disable for the host principal: same rules, no admin check.
func (s *Service) DisableByHost(ctx context.Context, name string) error {
	return s.hostTx(ctx, func(tx *sql.Tx, host uuid.UUID) error {
		return s.disable(ctx, tx, access.Actor{ID: host}, name)
	})
}

// EnableByHost is Enable for the host principal: same rules, no admin check.
func (s *Service) EnableByHost(ctx context.Context, name string) (string, error) {
	var next string
	err := s.hostTx(ctx, func(tx *sql.Tx, host uuid.UUID) (err error) {
		next, err = s.enable(ctx, tx, access.Actor{ID: host}, name)
		return err
	})
	return next, err
}

// Enable lifts a disable. Admin only. A person who never finished enrolling goes back to enrolling; the tokens
// revoked by the disable stay revoked. A machine whose owner is disabled stays disabled. It returns the new status.
func (s *Service) Enable(ctx context.Context, a access.Actor, name string) (string, error) {
	var next string
	err := access.AdminTx(ctx, s.p, s.log, a, "update", func(tx *sql.Tx) (err error) {
		next, err = s.enable(ctx, tx, a, name)
		return err
	})
	return next, err
}

func (s *Service) enable(ctx context.Context, tx *sql.Tx, a access.Actor, name string) (string, error) {
	id, _, err := s.find(ctx, tx, name)
	if err != nil {
		return "", err
	}
	var kind, status string
	var owner uuid.NullUUID
	if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT kind, status, owner_id FROM principals WHERE id = ?`), id).Scan(&kind, &status, &owner); err != nil {
		return "", err
	}
	if status != "disabled" {
		return "", access.Fail(access.CodeConflict, "that identity is not disabled")
	}
	if owner.Valid {
		var os string
		if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT status FROM principals WHERE id = ?`), owner.UUID).Scan(&os); err != nil {
			return "", err
		}
		if os == "disabled" {
			return "", access.Fail(access.CodeConflict, "its owner is disabled: enable the owner first")
		}
	}
	next := "active"
	if kind == "human" {
		var n int
		if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT COUNT(*) FROM credentials WHERE principal_id = ?`), id).Scan(&n); err != nil {
			return "", err
		}
		if n == 0 {
			next = "invited"
		}
	}
	if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE principals SET status = ? WHERE id = ?`), next, id); err != nil {
		return "", err
	}
	return next, s.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: "update", IP: a.IP, TargetType: "principal", TargetID: &id,
		Metadata: map[string]any{"change": "enabled", "status": next}})
}

// ResetFactorsByHost is for a person who lost their passkey and recovery codes. In one transaction it deletes their
// second factors and recovery codes, ends their sessions and puts them back into enrollment; the returned link
// leads through sign-in to enrolling a new factor (which also issues new recovery codes).
func (s *Service) ResetFactorsByHost(ctx context.Context, email string) (Invite, error) {
	var inv Invite
	err := s.hostTx(ctx, func(tx *sql.Tx, host uuid.UUID) error {
		id, role, err := s.find(ctx, tx, email)
		if err != nil {
			return err
		}
		var status string
		if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT status FROM principals WHERE id = ?`), id).Scan(&status); err != nil {
			return err
		}
		switch {
		case role == "":
			return access.Fail(access.CodeInvalid, "machines have no passkeys or authenticator apps")
		case status == "disabled":
			return access.Fail(access.CodeConflict, "that person is disabled: enable them first")
		case status == "invited":
			return access.Fail(access.CodeConflict, "that person has not enrolled yet: use `ku-server user invite`")
		}
		var factors, codes int64
		for _, q := range []struct {
			table string
			n     *int64
		}{{"credentials", &factors}, {"recovery_codes", &codes}} {
			res, err := tx.ExecContext(ctx, s.p.Rebind(`DELETE FROM `+q.table+` WHERE principal_id = ?`), id)
			if err != nil {
				return err
			}
			if *q.n, err = res.RowsAffected(); err != nil {
				return err
			}
		}
		sessions, err := s.tokens.RevokeAll(ctx, tx, id)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE principals SET status = 'invited' WHERE id = ?`), id); err != nil {
			return err
		}
		iss, err := s.tokens.Issue(ctx, tx, id, auth.KindInvite, nil, auth.AdminInviteTTL)
		if err != nil {
			return err
		}
		inv = Invite{iss.Raw, iss.ExpiresAt}
		return s.log.Append(ctx, tx, audit.Entry{Principal: host, Action: "update", TargetType: "principal", TargetID: &id,
			Metadata: map[string]any{"change": "reset_factors", "factors_removed": factors, "recovery_codes_removed": codes, "tokens_revoked": sessions}})
	})
	return inv, err
}
