// Package identity manages principals: invites, roles, status.
package identity

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/access"
	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/auth"
	"github.com/victorlunam/kuukura/storage"
)

type Service struct {
	p      storage.Provider
	log    *audit.Log
	tokens *auth.Tokens
}

func New(p storage.Provider, log *audit.Log, tokens *auth.Tokens) *Service {
	return &Service{p, log, tokens}
}

var (
	machineRE = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	emailRE   = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
)

// Invite is returned once; Token is the secret part of the link.
type Invite struct {
	Token     string
	ExpiresAt time.Time
}

// InviteHuman invites a person as a member. Admin only.
func (s *Service) InviteHuman(ctx context.Context, a access.Actor, email string) (Invite, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !emailRE.MatchString(email) {
		return Invite{}, access.Fail(access.CodeInvalid, "invalid email")
	}
	var inv Invite
	err := access.AdminTx(ctx, s.p, s.log, a, "invite", func(tx *sql.Tx) error {
		id, err := s.createHuman(ctx, tx, email, "member")
		if err != nil {
			return err
		}
		iss, err := s.tokens.Issue(ctx, tx, id, auth.KindInvite, nil, auth.InviteTTL)
		if err != nil {
			return err
		}
		inv = Invite{iss.Raw, iss.ExpiresAt}
		return s.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: "invite", IP: a.IP, TargetType: "principal", TargetID: &id,
			Metadata: map[string]any{"kind": "human"}})
	})
	return inv, err
}

// InviteMachine creates a machine identity owned by the admin and returns its key once.
func (s *Service) InviteMachine(ctx context.Context, a access.Actor, name string) (Invite, error) {
	if !machineRE.MatchString(name) || name == HostName {
		return Invite{}, access.Fail(access.CodeInvalid, "machine names use a-z, 0-9, dot, dash, underscore ("+HostName+" is reserved)")
	}
	var inv Invite
	err := access.AdminTx(ctx, s.p, s.log, a, "invite", func(tx *sql.Tx) error {
		if err := s.nameFree(ctx, tx, name); err != nil {
			return err
		}
		id := uuid.New()
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`INSERT INTO principals (id, kind, name, owner_id, status) VALUES (?, 'machine', ?, ?, 'active')`), id, name, a.ID); err != nil {
			return err
		}
		iss, err := s.tokens.Issue(ctx, tx, id, auth.KindMachineKey, []string{auth.ScopeRead, auth.ScopeWrite}, auth.MachineKeyTTL)
		if err != nil {
			return err
		}
		inv = Invite{iss.Raw, iss.ExpiresAt}
		if err := s.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: "invite", IP: a.IP, TargetType: "principal", TargetID: &id,
			Metadata: map[string]any{"kind": "machine"}}); err != nil {
			return err
		}
		return s.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: "token_create", IP: a.IP, TargetType: "token", TargetID: &iss.ID,
			Metadata: map[string]any{"kind": "machine_key"}})
	})
	return inv, err
}

// BootstrapAdmin is the server-side first-admin invite (15 min); see InviteByHost.
func (s *Service) BootstrapAdmin(ctx context.Context, email string) (Invite, error) {
	return s.InviteByHost(ctx, email, true)
}

func (s *Service) createHuman(ctx context.Context, tx *sql.Tx, email, role string) (uuid.UUID, error) {
	if err := s.nameFree(ctx, tx, email); err != nil {
		return uuid.Nil, err
	}
	id := uuid.New()
	_, err := tx.ExecContext(ctx, s.p.Rebind(`INSERT INTO principals (id, kind, name, email, role, status) VALUES (?, 'human', ?, ?, ?, 'invited')`), id, email, email, role)
	return id, err
}

func (s *Service) nameFree(ctx context.Context, tx *sql.Tx, name string) error {
	var n int
	if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT (SELECT COUNT(*) FROM principals WHERE name = ?) + (SELECT COUNT(*) FROM groups WHERE name = ?)`), name, name).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return access.Fail(access.CodeConflict, "that name is already used")
	}
	return nil
}

// lastAdminCheck fails if removing admin power from target would leave no active admin.
func (s *Service) lastAdminCheck(ctx context.Context, tx *sql.Tx, target uuid.UUID) error {
	var n int
	if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT COUNT(*) FROM principals WHERE role = 'admin' AND status = 'active' AND id <> ?`), target).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return access.Fail(access.CodeLastAdmin, "the last admin cannot be removed, disabled or demoted")
	}
	return nil
}

func (s *Service) find(ctx context.Context, tx *sql.Tx, name string) (id uuid.UUID, role string, err error) {
	var r sql.NullString
	name = strings.ToLower(name)
	err = sql.ErrNoRows // the host principal is not an identity anyone manages
	if name != HostName {
		err = tx.QueryRowContext(ctx, s.p.Rebind(`SELECT id, role FROM principals WHERE name = ?`), name).Scan(&id, &r)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return id, "", access.Fail(access.CodeNotFound, "unknown identity: "+name)
	}
	return id, r.String, err
}

// SetRole changes a human's role. Admin only; the last admin cannot be demoted.
func (s *Service) SetRole(ctx context.Context, a access.Actor, name, role string) error {
	if role != "admin" && role != "member" {
		return access.Fail(access.CodeInvalid, "role must be admin or member")
	}
	return access.AdminTx(ctx, s.p, s.log, a, "role_change", func(tx *sql.Tx) error {
		id, cur, err := s.find(ctx, tx, name)
		if err != nil {
			return err
		}
		if cur == "" {
			return access.Fail(access.CodeInvalid, "machines have no role")
		}
		if cur == "admin" && role != "admin" {
			if err := s.lastAdminCheck(ctx, tx, id); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE principals SET role = ? WHERE id = ?`), role, id); err != nil {
			return err
		}
		return s.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: "role_change", IP: a.IP, TargetType: "principal", TargetID: &id,
			Metadata: map[string]any{"from": cur, "to": role}})
	})
}

// Disable blocks login and ends every token of an identity; history is kept.
func (s *Service) Disable(ctx context.Context, a access.Actor, name string) error {
	return access.AdminTx(ctx, s.p, s.log, a, "disable", func(tx *sql.Tx) error {
		return s.disable(ctx, tx, a, name)
	})
}

func (s *Service) disable(ctx context.Context, tx *sql.Tx, a access.Actor, name string) error {
	id, role, err := s.find(ctx, tx, name)
	if err != nil {
		return err
	}
	if role == "admin" {
		if err := s.lastAdminCheck(ctx, tx, id); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE principals SET status = 'disabled' WHERE id = ?`), id); err != nil {
		return err
	}
	n, err := s.tokens.RevokeAll(ctx, tx, id)
	if err != nil {
		return err
	}
	// machines never outlive their owner
	rows, err := tx.QueryContext(ctx, s.p.Rebind(`SELECT id FROM principals WHERE owner_id = ?`), id)
	if err != nil {
		return err
	}
	var owned []uuid.UUID
	for rows.Next() {
		var m uuid.UUID
		if err := rows.Scan(&m); err != nil {
			_ = rows.Close()
			return err
		}
		owned = append(owned, m)
	}
	_ = rows.Close()
	for _, m := range owned {
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE principals SET status = 'disabled' WHERE id = ?`), m); err != nil {
			return err
		}
		c, err := s.tokens.RevokeAll(ctx, tx, m)
		if err != nil {
			return err
		}
		n += c
	}
	return s.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: "disable", IP: a.IP, TargetType: "principal", TargetID: &id,
		Metadata: map[string]any{"tokens_revoked": int(n)}})
}

// RequireAdmin fails unless the actor is an active admin; a failure is audited as a denial.
func (s *Service) RequireAdmin(ctx context.Context, a access.Actor, action string) error {
	return access.AdminTx(ctx, s.p, s.log, a, action, func(*sql.Tx) error { return nil })
}
