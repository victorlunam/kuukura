package auth

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

func newPrincipal(t *testing.T, p storage.Provider, status string) uuid.UUID {
	id := uuid.New()
	if _, err := p.DB().Exec(p.Rebind(`INSERT INTO principals (id, kind, name, email, role, status) VALUES (?, 'human', ?, 'x@example.test', 'member', ?)`), id, id.String(), status); err != nil {
		t.Fatal(err)
	}
	return id
}

func issue(t *testing.T, tk *Tokens, who uuid.UUID, kind string, scopes []string, ttl time.Duration) Issued {
	var iss Issued
	err := storage.InTx(t.Context(), tk.p, func(tx *sql.Tx) error {
		var err error
		iss, err = tk.Issue(t.Context(), tx, who, kind, scopes, ttl)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

func TestTokenLifecycle(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		tk := NewTokens(p)
		clock := time.Now().UTC()
		tk.Now = func() time.Time { return clock }
		who := newPrincipal(t, p, "active")

		s := issue(t, tk, who, KindSession, []string{ScopeRead, ScopeWrite}, SessionTTL)
		if !strings.HasPrefix(s.Raw, "ku_") {
			t.Fatal("prefix")
		}
		var n int
		if err := p.DB().QueryRow(p.Rebind(`SELECT COUNT(*) FROM tokens WHERE token_hash = ?`), []byte(s.Raw)).Scan(&n); err != nil || n != 0 {
			t.Fatal("only the hash may be stored")
		}
		info, err := tk.Validate(ctx, s.Raw)
		if err != nil || !info.HasScope(ScopeWrite) || info.Machine {
			t.Fatalf("%+v %v", info, err)
		}

		// idle timeout: unused for over an hour
		clock = clock.Add(IdleTimeout - time.Minute)
		if _, err := tk.Validate(ctx, s.Raw); err != nil {
			t.Fatalf("use within idle window: %v", err)
		}
		clock = clock.Add(IdleTimeout - time.Minute) // use refreshed the idle timer
		if _, err := tk.Validate(ctx, s.Raw); err != nil {
			t.Fatalf("idle timer must reset on use: %v", err)
		}
		clock = clock.Add(IdleTimeout + time.Minute)
		if _, err := tk.Validate(ctx, s.Raw); !errors.Is(err, ErrInvalid) {
			t.Fatal("idle session must expire")
		}

		// absolute expiry, even with constant use: 9 uses 50 minutes apart stay inside the 8 hours (450 min), and the
		// next one is past them although the session was used less than an hour before (never idle)
		clock = time.Now().UTC()
		s2 := issue(t, tk, who, KindSession, []string{ScopeRead}, SessionTTL)
		for range 9 {
			clock = clock.Add(50 * time.Minute)
			if _, err := tk.Validate(ctx, s2.Raw); err != nil {
				t.Fatalf("a session in constant use stays valid within 8h: %v", err)
			}
		}
		clock = clock.Add(50 * time.Minute)
		if _, err := tk.Validate(ctx, s2.Raw); !errors.Is(err, ErrInvalid) {
			t.Fatal("session must expire after 8h absolute")
		}

		// revoke
		clock = time.Now().UTC()
		s3 := issue(t, tk, who, KindSession, []string{ScopeRead}, SessionTTL)
		if err := tk.Revoke(ctx, p.DB(), s3.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := tk.Validate(ctx, s3.Raw); !errors.Is(err, ErrInvalid) {
			t.Fatal("revoked token")
		}
		for _, bad := range []string{"", "ku_", "nope", "ku_" + strings.Repeat("A", 43)} {
			if _, err := tk.Validate(ctx, bad); !errors.Is(err, ErrInvalid) {
				t.Fatalf("%q must be invalid", bad)
			}
		}

		// machine keys have no idle timeout but do expire
		m := issue(t, tk, who, KindMachineKey, []string{ScopeRead}, MachineKeyTTL)
		clock = clock.Add(30 * 24 * time.Hour)
		if _, err := tk.Validate(ctx, m.Raw); err != nil {
			t.Fatalf("machine key idle for 30 days: %v", err)
		}
		clock = clock.Add(61 * 24 * time.Hour)
		if _, err := tk.Validate(ctx, m.Raw); !errors.Is(err, ErrInvalid) {
			t.Fatal("machine key must expire")
		}
	})
}

func TestInviteSingleUseAndExpiry(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		tk := NewTokens(p)
		clock := time.Now().UTC()
		tk.Now = func() time.Time { return clock }
		who := newPrincipal(t, p, "invited")

		inv := issue(t, tk, who, KindInvite, nil, AdminInviteTTL)
		if _, err := tk.Validate(ctx, inv.Raw); !errors.Is(err, ErrInvalid) {
			t.Fatal("an invite is not a bearer token")
		}
		got, err := tk.ConsumeInvite(ctx, p.DB(), inv.Raw)
		if err != nil || got != who {
			t.Fatalf("consume: %v", err)
		}
		if _, err := tk.ConsumeInvite(ctx, p.DB(), inv.Raw); !errors.Is(err, ErrInvalid) {
			t.Fatal("invite must be single use")
		}

		late := issue(t, tk, who, KindInvite, nil, AdminInviteTTL)
		clock = clock.Add(AdminInviteTTL + time.Second)
		if _, err := tk.ConsumeInvite(ctx, p.DB(), late.Raw); !errors.Is(err, ErrInvalid) {
			t.Fatal("expired invite")
		}
		if _, err := tk.PeekInvite(ctx, late.Raw); !errors.Is(err, ErrInvalid) {
			t.Fatal("expired invite peek")
		}
	})
}
