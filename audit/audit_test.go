package audit

import (
	"bytes"
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

func principal(t *testing.T, p storage.Provider) uuid.UUID {
	id := uuid.New()
	if _, err := p.DB().Exec(p.Rebind(`INSERT INTO principals (id, kind, name, role, status) VALUES (?, 'human', ?, 'admin', 'active')`), id, "p-"+id.String()); err != nil {
		t.Fatal(err)
	}
	return id
}

// unprotect lets a test edit audit rows as the table owner would, bypassing the insert-only protection.
func unprotect(t *testing.T, p storage.Provider, kind string, triggers ...string) {
	t.Helper()
	if kind != "sqlite" {
		return
	}
	for _, tr := range triggers {
		if _, err := p.DB().Exec(`DROP TRIGGER ` + tr); err != nil {
			t.Fatal(err)
		}
	}
}

func TestChainVerifiesAndDetectsTamper(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		l := New(p)
		who := principal(t, p)
		v := 2
		for i := range 5 {
			e := Entry{Principal: who, Action: "list", IP: "203.0.113.7", Metadata: map[string]any{"count": i, "note": "é<>&\n"}}
			if i == 3 {
				e.Version = &v
				e.Result = ResultDenied
			}
			if err := l.Record(ctx, e); err != nil {
				t.Fatal(err)
			}
		}
		head, err := l.VerifyHead(ctx)
		if err != nil {
			t.Fatalf("clean chain must verify: %v", err)
		}
		var last []byte
		if err := p.DB().QueryRow(`SELECT hash FROM audit_log ORDER BY at DESC LIMIT 1`).Scan(&last); err != nil {
			t.Fatal(err)
		}
		if head.Rows != 5 || !bytes.Equal(head.Hash, last) {
			t.Fatalf("head %d %x, want 5 %x", head.Rows, head.Hash, last)
		}
		unprotect(t, p, kind, "audit_log_no_update")
		if _, err := p.DB().Exec(`UPDATE audit_log SET result = 'ok' WHERE result = 'denied'`); err != nil {
			t.Fatal(err)
		}
		if err := l.Verify(ctx); err == nil {
			t.Fatal("tampered row must be detected")
		}
	})
}

func TestChainDetectsDeletedRow(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		l := New(p)
		who := principal(t, p)
		for range 3 {
			if err := l.Record(ctx, Entry{Principal: who, Action: "list"}); err != nil {
				t.Fatal(err)
			}
		}
		unprotect(t, p, kind, "audit_log_no_delete")
		if _, err := p.DB().Exec(`DELETE FROM audit_log WHERE id = (SELECT id FROM audit_log ORDER BY at LIMIT 1 OFFSET 1)`); err != nil {
			t.Fatal(err)
		}
		if err := l.Verify(ctx); err == nil {
			t.Fatal("deleted row must be detected")
		}
	})
}

// Verify rereads the canonical text of the address, so the hash must cover that form: X-Forwarded-For from a
// trusted hop can carry any spelling.
func TestNonCanonicalIPStillVerifies(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		l := New(p)
		who := principal(t, p)
		want := map[string]string{
			"FD00:0::1":                 "fd00::1",
			"2001:0DB8:0000:0000::0001": "2001:db8::1",
			"::FFFF:1.2.3.4":            "::ffff:1.2.3.4",
			"fe80::1%eth0":              "fe80::1",
			"203.0.113.7":               "203.0.113.7",
		}
		for in := range want {
			if err := l.Record(ctx, Entry{Principal: who, Action: "list", IP: in}); err != nil {
				t.Fatalf("%s: %v", in, err)
			}
		}
		if err := l.Verify(ctx); err != nil {
			t.Fatalf("non-canonical addresses must verify: %v", err)
		}
		rows, err := l.List(ctx, Filter{}, 50)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, r := range rows {
			got[r.IP] = true
		}
		for in, w := range want {
			if !got[w] {
				t.Errorf("%s: stored form %q not found in %v", in, w, got)
			}
		}
		if err := l.Record(ctx, Entry{Principal: who, Action: "list", IP: "not an ip"}); err == nil {
			t.Fatal("a bad address must be refused")
		}
	})
}

// A rolled-back append must leave no row and no fork: the next append chains onto the last committed row.
func TestRolledBackAppendKeepsChain(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		l := New(p)
		who := principal(t, p)
		if err := l.Record(ctx, Entry{Principal: who, Action: "list"}); err != nil {
			t.Fatal(err)
		}
		boom := errors.New("boom")
		err := storage.InTx(ctx, p, func(tx *sql.Tx) error {
			if err := l.Append(ctx, tx, Entry{Principal: who, Action: "list"}); err != nil {
				return err
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("got %v", err)
		}
		if err := l.Record(ctx, Entry{Principal: who, Action: "list"}); err != nil {
			t.Fatal(err)
		}
		head, err := l.VerifyHead(ctx)
		if err != nil || head.Rows != 2 {
			t.Fatalf("chain after rollback: %+v %v", head, err)
		}
	})
}

// Concurrent appends (several connections on Postgres, the advisory lock) must form one linear chain.
func TestConcurrentAppendsStayLinear(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		l := New(p)
		who := principal(t, p)
		const workers, each = 8, 10
		var wg sync.WaitGroup
		errs := make(chan error, workers*each)
		for range workers {
			wg.Go(func() {
				for range each {
					errs <- l.Record(ctx, Entry{Principal: who, Action: "list"})
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		head, err := l.VerifyHead(ctx)
		if err != nil || head.Rows != workers*each {
			t.Fatalf("chain after concurrent appends: %+v %v", head, err)
		}
		var distinct int
		if err := p.DB().QueryRow(`SELECT COUNT(DISTINCT at) FROM audit_log`).Scan(&distinct); err != nil {
			t.Fatal(err)
		}
		if distinct != workers*each {
			t.Fatalf("%d distinct timestamps, want %d: the tip lookup relies on them", distinct, workers*each)
		}
	})
}

// If the newest row by time already has a successor (an edited timestamp), the tip is still found by the chain.
func TestTipFallsBackToTheChain(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		l := New(p)
		who := principal(t, p)
		for range 2 {
			if err := l.Record(ctx, Entry{Principal: who, Action: "list"}); err != nil {
				t.Fatal(err)
			}
		}
		var second []byte
		if err := p.DB().QueryRow(`SELECT hash FROM audit_log ORDER BY at DESC LIMIT 1`).Scan(&second); err != nil {
			t.Fatal(err)
		}
		unprotect(t, p, kind, "audit_log_no_update")
		if _, err := p.DB().Exec(p.Rebind(`UPDATE audit_log SET at = ? WHERE hash <> ?`), p.TimeArg(storage.Time{}.Time.AddDate(3000, 0, 0)), second); err != nil {
			t.Fatal(err)
		}
		if err := l.Record(ctx, Entry{Principal: who, Action: "list"}); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := p.DB().QueryRow(p.Rebind(`SELECT COUNT(*) FROM audit_log WHERE prev_hash = ?`), second).Scan(&n); err != nil || n != 1 {
			t.Fatalf("the new row must chain onto the real tip: %d %v", n, err)
		}
	})
}

func TestJCS(t *testing.T) {
	got, err := jcs(map[string]any{"b": 1, "a": []any{"x\u2028", true, nil}, "é": "\u0001"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"a\":[\"x\u2028\",true,null],\"b\":1,\"é\":\"\\u0001\"}"; string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if _, err := jcs(1.5); err == nil {
		t.Fatal("floats must be rejected")
	}
}
