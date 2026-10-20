package secrets

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/victorlunam/kuukura/internal/access"
	"github.com/victorlunam/kuukura/internal/keys"
	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

// race runs fn n times at once and returns each call's error.
func race(n int, fn func(i int) error) []error {
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			<-start
			errs[i] = fn(i)
		})
	}
	close(start)
	wg.Wait()
	return errs
}

// Writers of one secret take turns: every one of them succeeds and gets its own version number.
func TestConcurrentSetsOfOneSecret(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")
		e.set(u, "CONC", "v0-FAKE", "app:shop")

		const n = 8
		versions := make([]int, n)
		for i, err := range race(n, func(i int) error {
			r, err := e.svc.Set(ctx, u, SetInput{Name: "CONC", Tags: []string{"app:shop"}, Value: fmt.Appendf(nil, "v%d-FAKE", i)})
			versions[i] = r.Version
			return err
		}) {
			if err != nil {
				t.Fatalf("writer %d: %v", i, err)
			}
		}
		slices.Sort(versions)
		for i, v := range versions {
			if v != i+2 {
				t.Fatalf("versions %v, want 2..%d", versions, n+1)
			}
		}
		if err := e.log.Verify(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

// Of several creators of one new identity, one creates it and the others either add a version to it or are told
// to retry; none gets a database error.
func TestConcurrentCreatesOfOneSecret(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")

		const n = 8
		versions := make([]int, n)
		var created int
		var mu sync.Mutex
		ok := 0
		for i, err := range race(n, func(i int) error {
			r, err := e.svc.Set(ctx, u, SetInput{Name: "FRESH", Tags: []string{"app:shop"}, Value: fmt.Appendf(nil, "v%d-FAKE", i), Create: true})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				ok++
				versions[i] = r.Version
				if r.Created {
					created++
				}
			}
			return err
		}) {
			if err != nil && code(err) != access.CodeClash {
				t.Fatalf("creator %d: want success or a retryable clash, got %v", i, err)
			}
		}
		var rows, vers int
		if err := p.DB().QueryRow(`SELECT COUNT(*) FROM secrets`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if err := p.DB().QueryRow(`SELECT COUNT(*) FROM secret_versions`).Scan(&vers); err != nil {
			t.Fatal(err)
		}
		if rows != 1 || created != 1 || vers != ok {
			t.Fatalf("secrets %d, creations %d, versions %d for %d successes", rows, created, vers, ok)
		}
		if err := e.log.Verify(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

// Two renames onto one identity: one wins, the other gets a clash, not a database error.
func TestConcurrentRenamesClash(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")
		e.set(u, "FIRST", "v", "app:shop")
		e.set(u, "SECOND", "v", "app:shop")

		errs := race(2, func(i int) error {
			_, err := e.svc.Update(ctx, u, Selector{Name: []string{"FIRST", "SECOND"}[i]}, Change{Rename: "TARGET"}, false)
			return err
		})
		wins := 0
		for _, err := range errs {
			switch code(err) {
			case "<nil>":
				wins++
			case access.CodeClash:
			default:
				t.Fatalf("want success or a clash, got %v", err)
			}
		}
		if wins != 1 {
			t.Fatalf("exactly one rename wins, got %d: %v", wins, errs)
		}
	})
}

// lockProbe is a key provider that notes, at every unwrap, whether the audit lock is held by someone else. On
// Postgres the lock is an advisory transaction lock; on sqlite there is none and the probe only counts.
type lockProbe struct {
	keys.KeyProvider
	p       storage.Provider
	kind    string
	unwraps int
	held    bool
}

func (l *lockProbe) Unwrap(ctx context.Context, keyID string, wrapped, aad []byte) ([]byte, error) {
	l.unwraps++
	if l.kind == "postgres" {
		tx, err := l.p.DB().BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		var got bool
		const auditLockKey = 7266011 // storage's LockAudit
		if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock($1)`, auditLockKey).Scan(&got); err != nil {
			return nil, err
		}
		l.held = l.held || !got
	}
	return l.KeyProvider.Unwrap(ctx, keyID, wrapped, aad)
}

// Decrypting may mean a network call to KMS; it must happen before the first audit append, which takes the global lock.
func TestRunDecryptsBeforeTheAuditLock(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")
		e.set(u, "ONE", "a-FAKE", "app:shop")
		e.set(u, "TWO", "b-FAKE", "app:shop")

		probe := &lockProbe{KeyProvider: e.svc.kp, p: p, kind: kind}
		svc := New(p, probe, e.log)
		vals, err := svc.Run(ctx, u, Selector{Tags: []string{"app:shop"}}, false)
		if err != nil || len(vals) != 2 || probe.unwraps != 2 {
			t.Fatalf("run: %d values, %d unwraps, %v", len(vals), probe.unwraps, err)
		}
		if probe.held {
			t.Fatal("the audit lock was held while a secret was being decrypted")
		}
		if e.auditCount(u, "read", "ok") != 2 {
			t.Fatal("one audit row per secret read")
		}
	})
}
