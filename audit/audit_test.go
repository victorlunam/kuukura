package audit

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

var ctx = context.Background()

func principal(t *testing.T, p storage.Provider) uuid.UUID {
	id := uuid.New()
	if _, err := p.DB().Exec(p.Rebind(`INSERT INTO principals (id, kind, name, role, status) VALUES (?, 'human', ?, 'admin', 'active')`), id, "p-"+id.String()); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestChainVerifiesAndDetectsTamper(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		l := New(p)
		who := principal(t, p)
		v := 2
		for i := 0; i < 5; i++ {
			e := Entry{Principal: who, Action: "list", IP: "203.0.113.7", Metadata: map[string]any{"count": i, "note": "é<>&\n"}}
			if i == 3 {
				e.Version = &v
				e.Result = ResultDenied
			}
			if err := l.Record(ctx, e); err != nil {
				t.Fatal(err)
			}
		}
		if err := l.Verify(ctx); err != nil {
			t.Fatalf("clean chain must verify: %v", err)
		}
		// tamper as the table owner, bypassing the insert-only protection
		if kind == "sqlite" {
			if _, err := p.DB().Exec(`DROP TRIGGER audit_log_no_update`); err != nil {
				t.Fatal(err)
			}
		}
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
		l := New(p)
		who := principal(t, p)
		for i := 0; i < 3; i++ {
			if err := l.Record(ctx, Entry{Principal: who, Action: "list"}); err != nil {
				t.Fatal(err)
			}
		}
		if kind == "sqlite" {
			if _, err := p.DB().Exec(`DROP TRIGGER audit_log_no_delete`); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := p.DB().Exec(`DELETE FROM audit_log WHERE id = (SELECT id FROM audit_log ORDER BY at LIMIT 1 OFFSET 1)`); err != nil {
			t.Fatal(err)
		}
		if err := l.Verify(ctx); err == nil {
			t.Fatal("deleted row must be detected")
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
