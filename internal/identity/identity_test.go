package identity

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/access"
	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/auth"
	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

type env struct {
	t      *testing.T
	p      storage.Provider
	svc    *Service
	tokens *auth.Tokens
	log    *audit.Log
}

func setup(t *testing.T, p storage.Provider) *env {
	log := audit.New(p)
	tk := auth.NewTokens(p)
	return &env{t, p, New(p, log, tk), tk, log}
}

func (e *env) person(role, status string) access.Actor {
	return access.Actor{ID: storagetest.Principal(e.t, e.p, "human", role, status)}
}

func (e *env) name(a access.Actor) string {
	var n string
	if err := e.p.DB().QueryRow(e.p.Rebind(`SELECT name FROM principals WHERE id = ?`), a.ID).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func code(err error) string {
	var de *access.Error
	if errors.As(err, &de) {
		return de.Code
	}
	return "other"
}

func (e *env) count(q string, args ...any) int {
	var n int
	if err := e.p.DB().QueryRow(e.p.Rebind(q), args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func TestOnlyAdminsInvite(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		admin := e.person("admin", "active")
		member := e.person("member", "active")
		if _, err := e.svc.InviteHuman(ctx, member, "new@example.test"); code(err) != access.CodeDenied {
			t.Fatalf("member invite: %v", err)
		}
		if e.count(`SELECT COUNT(*) FROM audit_log WHERE principal_id = ? AND action = 'invite' AND result = 'denied'`, member.ID) != 1 {
			t.Fatal("denial must be audited")
		}
		inv, err := e.svc.InviteHuman(ctx, admin, "New@Example.test")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(inv.Token, "ku_") || time.Until(inv.ExpiresAt) > 24*time.Hour+time.Minute || time.Until(inv.ExpiresAt) < 23*time.Hour {
			t.Fatalf("invite: %+v", inv)
		}
		if e.count(`SELECT COUNT(*) FROM principals WHERE name = 'new@example.test' AND status = 'invited' AND role = 'member'`) != 1 {
			t.Fatal("invite must create an invited member")
		}
		if _, err := e.svc.InviteHuman(ctx, admin, "new@example.test"); code(err) != access.CodeConflict {
			t.Fatalf("duplicate invite: %v", err)
		}
		if err := e.log.Verify(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func TestBootstrapAdminInvite(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		inv, err := e.svc.BootstrapAdmin(ctx, "first@example.test")
		if err != nil {
			t.Fatal(err)
		}
		if d := time.Until(inv.ExpiresAt); d > 15*time.Minute || d < 14*time.Minute {
			t.Fatalf("ttl %v", d)
		}
		if e.count(`SELECT COUNT(*) FROM principals WHERE role = 'admin' AND status = 'invited'`) != 1 {
			t.Fatal("first admin")
		}
		rows, _ := e.log.List(ctx, audit.Filter{}, 10)
		if len(rows) != 1 || rows[0].Action != "invite" {
			t.Fatal("must be audited")
		}
		for _, v := range rows[0].Metadata {
			if s, _ := v.(string); strings.Contains(s, inv.Token) {
				t.Fatal("link in audit")
			}
		}
		// only the hash is stored: the SHA-256 of the raw token is there, the raw token is not
		sum := sha256.Sum256([]byte(inv.Token))
		if e.count(`SELECT COUNT(*) FROM tokens WHERE token_hash = ?`, sum[:]) != 1 {
			t.Fatal("the token's hash must be stored")
		}
		if e.count(`SELECT COUNT(*) FROM tokens WHERE token_hash = ?`, []byte(inv.Token)) != 0 {
			t.Fatal("raw token stored")
		}
		// a second bootstrap for an existing admin is a break-glass re-invite
		if _, err := e.svc.BootstrapAdmin(ctx, "first@example.test"); err != nil {
			t.Fatal(err)
		}
		member := e.person("member", "active")
		if _, err := e.svc.BootstrapAdmin(ctx, e.name(member)); code(err) != access.CodeConflict {
			t.Fatalf("bootstrap must not touch members: %v", err)
		}
	})
}

func TestLastAdminProtected(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		a1 := e.person("admin", "active")
		if err := e.svc.Disable(ctx, a1, e.name(a1)); code(err) != access.CodeLastAdmin {
			t.Fatalf("disable last admin: %v", err)
		}
		if err := e.svc.SetRole(ctx, a1, e.name(a1), "member"); code(err) != access.CodeLastAdmin {
			t.Fatalf("demote last admin: %v", err)
		}
		a2 := e.person("admin", "active")
		if err := e.svc.SetRole(ctx, a1, e.name(a2), "member"); err != nil {
			t.Fatalf("demote with another admin around: %v", err)
		}
		// a2 is a member now, so a1 is the last admin again
		if err := e.svc.Disable(ctx, a1, e.name(a1)); code(err) != access.CodeLastAdmin {
			t.Fatalf("a1 is last again: %v", err)
		}
		// an invited (not active) admin does not count
		e.person("admin", "invited")
		if err := e.svc.Disable(ctx, a1, e.name(a1)); code(err) != access.CodeLastAdmin {
			t.Fatalf("invited admins do not count: %v", err)
		}
	})
}

func TestDisableEndsTokensAndMachines(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		admin := e.person("admin", "active")
		user := e.person("member", "active")
		sess, err := e.issue(user.ID, auth.KindSession, []string{"read"})
		if err != nil {
			t.Fatal(err)
		}
		// a machine owned by the user
		mid := storagetest.Machine(t, p, user.ID, "ci")
		mkey, err := e.issue(mid, auth.KindMachineKey, []string{"read"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.tokens.Validate(ctx, sess); err != nil {
			t.Fatal(err)
		}
		if err := e.svc.Disable(ctx, admin, e.name(user)); err != nil {
			t.Fatal(err)
		}
		for _, tok := range []string{sess, mkey} {
			if _, err := e.tokens.Validate(ctx, tok); !errors.Is(err, auth.ErrInvalid) {
				t.Fatal("tokens of a disabled identity and its machines must stop working")
			}
		}
		// the tokens fail because the identities are disabled, not by some other accident
		for _, id := range []uuid.UUID{user.ID, mid} {
			if e.count(`SELECT COUNT(*) FROM principals WHERE id = ? AND status = 'disabled'`, id) != 1 {
				t.Fatalf("%s must be disabled", id)
			}
		}
		if e.count(`SELECT COUNT(*) FROM tokens WHERE revoked_at IS NULL AND principal_id IN (?, ?)`, user.ID, mid) != 0 {
			t.Fatal("every token of the person and the machine must be revoked")
		}
		if e.count(`SELECT COUNT(*) FROM audit_log WHERE action = 'disable'`) != 1 {
			t.Fatal("disable must be audited")
		}
	})
}

func (e *env) issue(id uuid.UUID, kind string, scopes []string) (string, error) {
	var raw string
	err := storage.InTx(e.t.Context(), e.p, func(tx *sql.Tx) error {
		iss, err := e.tokens.Issue(e.t.Context(), tx, id, kind, scopes, time.Hour)
		raw = iss.Raw
		return err
	})
	return raw, err
}

func TestMachineInvite(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		admin := e.person("admin", "active")
		inv, err := e.svc.InviteMachine(ctx, admin, "ci-deploy")
		if err != nil {
			t.Fatal(err)
		}
		info, err := e.tokens.Validate(ctx, inv.Token)
		if err != nil || !info.Machine || info.Role != "" || info.Kind != auth.KindMachineKey {
			t.Fatalf("%+v %v", info, err)
		}
		if _, err := e.svc.InviteMachine(ctx, admin, "Bad Name"); code(err) != access.CodeInvalid {
			t.Fatal("machine name validation")
		}
		if err := e.svc.SetRole(ctx, admin, "ci-deploy", "admin"); code(err) != access.CodeInvalid {
			t.Fatalf("machines are never admin: %v", err)
		}
	})
}
