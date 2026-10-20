package auth_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/auth"
	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

// human stores an active person, and factor gives them a second step directly: these tests are about managing
// factors, not about enrolling them.
func (e *env) human() auth.Info {
	id := uuid.New()
	if _, err := e.p.DB().Exec(e.p.Rebind(`INSERT INTO principals (id, kind, name, email, role, status) VALUES (?, 'human', ?, ?, 'member', 'active')`), id, id.String(), id.String()+"@example.test"); err != nil {
		e.t.Fatal(err)
	}
	return auth.Info{PrincipalID: id, Scopes: []string{auth.ScopeRead, auth.ScopeWrite}}
}

func (e *env) factor(who auth.Info) uuid.UUID {
	id := uuid.New()
	if _, err := e.p.DB().Exec(e.p.Rebind(`INSERT INTO credentials (id, principal_id, kind, encrypted_totp_secret, is_default)
		VALUES (?, ?, 'totp', ?, NOT EXISTS (SELECT 1 FROM credentials WHERE principal_id = ?))`), id, who.PrincipalID, []byte("x"), who.PrincipalID); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func TestRemoveFactorKeepsTheLastOne(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		me, other := e.human(), e.human()
		first, second := e.factor(me), e.factor(me)
		theirs := e.factor(other)

		if err := e.svc.RemoveFactor(ctx, me, theirs, "203.0.113.9"); !errors.Is(err, auth.ErrNoSuchFactor) {
			t.Fatalf("someone else's factor is not mine to remove: %v", err)
		}
		if err := e.svc.RemoveFactor(ctx, auth.Info{PrincipalID: me.PrincipalID, Machine: true}, first, "203.0.113.9"); !errors.Is(err, auth.ErrLogin) {
			t.Fatalf("machines have no factors: %v", err)
		}
		if err := e.svc.RemoveFactor(ctx, me, first, "203.0.113.9"); err != nil { // the default: the other one takes over
			t.Fatal(err)
		}
		fs, err := e.svc.ListFactors(ctx, me)
		if err != nil || len(fs) != 1 || fs[0].ID != second || !fs[0].Default {
			t.Fatalf("the remaining factor becomes the default: %+v %v", fs, err)
		}
		if err := e.svc.RemoveFactor(ctx, me, second, "203.0.113.9"); !errors.Is(err, auth.ErrLastFactor) {
			t.Fatalf("the last factor stays: %v", err)
		}
		if e.count(`SELECT COUNT(*) FROM audit_log WHERE action = 'update' AND target_type = 'principal'`) != 1 {
			t.Fatal("only the real removal is audited")
		}
	})
}

// Two removals at once must not both see "two left": the account keeps one second step (on postgres this needs
// the per-principal lock).
func TestConcurrentRemovalsKeepOneFactor(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		for range 25 {
			me := e.human()
			a, b := e.factor(me), e.factor(me)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for _, id := range []uuid.UUID{a, b} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					if err := e.svc.RemoveFactor(ctx, me, id, "203.0.113.9"); err != nil && !errors.Is(err, auth.ErrLastFactor) {
						t.Error(err)
					}
				}()
			}
			close(start)
			wg.Wait()
			if n := e.count(`SELECT COUNT(*) FROM credentials WHERE principal_id = ?`, me.PrincipalID); n != 1 {
				t.Fatalf("%d factors left after two concurrent removals, want 1", n)
			}
		}
	})
}

func TestSetDefaultFactor(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		me, other := e.human(), e.human()
		first, second := e.factor(me), e.factor(me)
		theirs := e.factor(other)

		if err := e.svc.SetDefaultFactor(ctx, me, theirs, "203.0.113.9"); !errors.Is(err, auth.ErrNoSuchFactor) {
			t.Fatalf("someone else's factor cannot be my default: %v", err)
		}
		if err := e.svc.SetDefaultFactor(ctx, me, second, "203.0.113.9"); err != nil {
			t.Fatal(err)
		}
		fs, err := e.svc.ListFactors(ctx, me)
		if err != nil || len(fs) != 2 {
			t.Fatalf("%+v %v", fs, err)
		}
		for _, f := range fs {
			if f.Default != (f.ID == second) {
				t.Fatalf("exactly the chosen factor is the default (first %s): %+v", first, fs)
			}
		}
	})
}

// The link that adds a factor works once, only for an active account, and opens a session that can do nothing else.
func TestOpenAddFactor(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		me := e.human()

		if _, err := e.svc.StartAddFactor(me, "sms"); !errors.Is(err, auth.ErrLogin) {
			t.Fatalf("only passkey and totp: %v", err)
		}
		if _, err := e.svc.StartAddFactor(auth.Info{PrincipalID: me.PrincipalID, Machine: true}, "totp"); !errors.Is(err, auth.ErrLogin) {
			t.Fatalf("machines have no factors: %v", err)
		}
		id, err := e.svc.StartAddFactor(me, "totp")
		if err != nil {
			t.Fatal(err)
		}
		pd, err := e.svc.OpenAddFactor(ctx, id)
		if err != nil || pd.Mode != "add" || pd.Add != "totp" || pd.PrincipalID != me.PrincipalID {
			t.Fatalf("open: %+v %v", pd, err)
		}
		if in := e.info(pd.Token); !in.HasScope(auth.ScopeEnroll) || in.HasScope(auth.ScopeRead) || in.HasScope(auth.ScopeWrite) {
			t.Fatalf("the session can only enroll: %v", in.Scopes)
		}
		if _, err := e.svc.OpenAddFactor(ctx, id); !errors.Is(err, auth.ErrLogin) {
			t.Fatalf("the link works once: %v", err)
		}
	})
}
