package storage

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// backends returns the backends to run: VAULT_STORAGE selects one, unset runs both.
// Postgres needs VAULT_TEST_POSTGRES_URL (an admin URL; each test gets its own database).
func backends(t *testing.T) []string {
	switch s := os.Getenv("VAULT_STORAGE"); s {
	case "":
		return []string{"sqlite", "postgres"}
	case "sqlite", "postgres":
		return []string{s}
	default:
		t.Fatalf("bad VAULT_STORAGE %q", s)
		return nil
	}
}

func forEachBackend(t *testing.T, fn func(t *testing.T, kind, dsn string)) {
	for _, kind := range backends(t) {
		t.Run(kind, func(t *testing.T) {
			fn(t, kind, newDSN(t, kind))
		})
	}
}

func newDSN(t *testing.T, kind string) string {
	if kind == "sqlite" {
		return filepath.Join(t.TempDir(), "kuukura.db")
	}
	admin := os.Getenv("VAULT_TEST_POSTGRES_URL")
	if admin == "" {
		t.Fatal("VAULT_TEST_POSTGRES_URL is required for the postgres backend")
	}
	p, err := Open(context.Background(), "postgres", admin)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	name := "kt_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := p.DB().Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p, err := Open(context.Background(), "postgres", admin)
		if err == nil {
			_, _ = p.DB().Exec("DROP DATABASE " + name + " WITH (FORCE)")
			p.Close()
		}
	})
	u, _ := url.Parse(admin)
	u.Path = "/" + name
	return u.String()
}

func open(t *testing.T, kind, dsn string) Provider {
	t.Helper()
	if err := Migrate(kind, dsn); err != nil {
		t.Fatal(err)
	}
	p, err := Open(context.Background(), kind, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func exec(t *testing.T, p Provider, q string, args ...any) error {
	t.Helper()
	_, err := p.DB().Exec(p.Rebind(q), args...)
	return err
}

func mustExec(t *testing.T, p Provider, q string, args ...any) {
	t.Helper()
	if err := exec(t, p, q, args...); err != nil {
		t.Fatal(err)
	}
}

func newPrincipal(t *testing.T, p Provider) string {
	id := uuid.NewString()
	mustExec(t, p, `INSERT INTO principals (id, kind, name, email, role, status) VALUES (?, 'human', ?, 'a@example.test', 'admin', 'active')`, id, "p-"+id)
	return id
}

func newSecret(t *testing.T, p Provider, by, name string, tags Tags) (string, error) {
	id := uuid.NewString()
	err := exec(t, p, `INSERT INTO secrets (id, name, kind, tags, created_by) VALUES (?, ?, 'text', ?, ?)`, id, name, p.TagsArg(tags), by)
	return id, err
}

func TestMigrationsReversible(t *testing.T) {
	forEachBackend(t, func(t *testing.T, kind, dsn string) {
		p := open(t, kind, dsn)
		m, err := migrator(kind, dsn)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if err := m.Rollback(); err != nil {
				t.Fatal(err)
			}
		}
		if err := exec(t, p, `SELECT 1 FROM principals`); err == nil {
			t.Fatal("principals still exists after full rollback")
		}
		if err := m.Migrate(); err != nil {
			t.Fatal(err)
		}
		if err := exec(t, p, `SELECT 1 FROM principals`); err != nil {
			t.Fatal(err)
		}
	})
}

func TestNormalizeTags(t *testing.T) {
	got, err := NormalizeTags([]string{"Env:Prod", "app:shop", "env:prod"})
	if err != nil || !slices.Equal(got, Tags{"app:shop", "env:prod"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range [][]string{{"nocolon"}, {"a:b:c"}, {"a:"}, {"A B:c"}} {
		if _, err := NormalizeTags(bad); err == nil {
			t.Fatalf("%v should be rejected", bad)
		}
	}
	many := make([]string, 11)
	for i := range many {
		many[i] = fmt.Sprintf("k:v%d", i)
	}
	if _, err := NormalizeTags(many); err == nil {
		t.Fatal("11 tags should be rejected")
	}
}

func TestTagsRoundTrip(t *testing.T) {
	forEachBackend(t, func(t *testing.T, kind, dsn string) {
		p := open(t, kind, dsn)
		by := newPrincipal(t, p)
		for _, want := range []Tags{{}, {"app:shop"}, {"app:shop", "env:prod", "team:pay"}} {
			id, err := newSecret(t, p, by, "RT_"+strings.ToUpper(strings.NewReplacer(":", "_", "-", "_").Replace(strings.Join(want, "_"))), want)
			if err != nil {
				t.Fatal(err)
			}
			var got Tags
			if err := p.DB().QueryRow(p.Rebind(`SELECT tags FROM secrets WHERE id = ?`), id).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, want) {
				t.Fatalf("got %v want %v", got, want)
			}
		}
	})
}

func TestUniqueNameTagsActiveOnly(t *testing.T) {
	forEachBackend(t, func(t *testing.T, kind, dsn string) {
		p := open(t, kind, dsn)
		by := newPrincipal(t, p)
		tags := Tags{"app:shop", "env:prod"}
		id, err := newSecret(t, p, by, "STRIPE_KEY", tags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := newSecret(t, p, by, "STRIPE_KEY", tags); err == nil {
			t.Fatal("duplicate name+tags must be rejected")
		}
		if _, err := newSecret(t, p, by, "STRIPE_KEY", Tags{"app:shop", "env:qa"}); err != nil {
			t.Fatalf("same name, other tags must be allowed: %v", err)
		}
		if _, err := newSecret(t, p, by, "stripe_key", Tags{"app:x"}); err == nil {
			t.Fatal("lowercase name must be rejected by CHECK")
		}
		now := "2026-10-19T00:00:00Z"
		if kind == "postgres" {
			mustExec(t, p, `UPDATE secrets SET archived_at = now(), archived_by = ? WHERE id = ?`, by, id)
		} else {
			mustExec(t, p, `UPDATE secrets SET archived_at = ?, archived_by = ? WHERE id = ?`, now, by, id)
		}
		if _, err := newSecret(t, p, by, "STRIPE_KEY", tags); err != nil {
			t.Fatalf("name+tags must be reusable after archive: %v", err)
		}
	})
}

func TestAuditLogInsertOnly(t *testing.T) {
	forEachBackend(t, func(t *testing.T, kind, dsn string) {
		p := open(t, kind, dsn)
		by := newPrincipal(t, p)
		ctx := context.Background()
		conn, err := p.DB().Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if kind == "postgres" {
			if _, err := conn.ExecContext(ctx, `SET ROLE kuukura_app`); err != nil {
				t.Fatal(err)
			}
		}
		id := uuid.NewString()
		ins := p.Rebind(`INSERT INTO audit_log (id, at, principal_id, action, result, prev_hash, hash)
			VALUES (?, ?, ?, 'login', 'ok', ?, ?)`)
		at := any("2026-10-19T00:00:00Z")
		if kind == "postgres" {
			at = "2026-10-19T00:00:00Z"
		}
		if _, err := conn.ExecContext(ctx, ins, id, at, by, make([]byte, 32), make([]byte, 32)); err != nil {
			t.Fatalf("insert must work: %v", err)
		}
		if _, err := conn.ExecContext(ctx, p.Rebind(`UPDATE audit_log SET result = 'denied' WHERE id = ?`), id); err == nil {
			t.Fatal("UPDATE on audit_log must fail")
		}
		if _, err := conn.ExecContext(ctx, p.Rebind(`DELETE FROM audit_log WHERE id = ?`), id); err == nil {
			t.Fatal("DELETE on audit_log must fail")
		}
	})
}

// Grant tag containment must give identical answers on both backends.
func TestGrantTagContainment(t *testing.T) {
	forEachBackend(t, func(t *testing.T, kind, dsn string) {
		p := open(t, kind, dsn)
		by := newPrincipal(t, p)
		secrets := map[string]Tags{
			"S_NONE":  {},
			"S_SHOP":  {"app:shop"},
			"S_PROD":  {"app:shop", "env:prod"},
			"S_PAY":   {"app:shop", "env:prod", "team:pay"},
			"S_OTHER": {"app:shop2", "env:prod"}, // prefix lookalike of app:shop
		}
		for n, tags := range secrets {
			if _, err := newSecret(t, p, by, n, tags); err != nil {
				t.Fatal(err)
			}
		}
		cases := []struct {
			sel  Tags
			want []string
		}{
			{Tags{}, []string{"S_NONE", "S_OTHER", "S_PAY", "S_PROD", "S_SHOP"}},
			{Tags{"app:shop"}, []string{"S_PAY", "S_PROD", "S_SHOP"}},
			{Tags{"app:shop", "env:prod"}, []string{"S_PAY", "S_PROD"}},
			{Tags{"env:prod", "team:pay"}, []string{"S_PAY"}},
			{Tags{"env:qa"}, nil},
		}
		for _, c := range cases {
			cond, args := p.Contains("tags", c.sel)
			rows, err := p.DB().Query(p.Rebind(`SELECT name FROM secrets WHERE `+cond+` ORDER BY name`), args...)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for rows.Next() {
				var n string
				if err := rows.Scan(&n); err != nil {
					t.Fatal(err)
				}
				got = append(got, n)
			}
			rows.Close()
			if !slices.Equal(got, c.want) {
				t.Fatalf("selector %v: got %v want %v", c.sel, got, c.want)
			}
		}
	})
}

func TestCheckAuditProtected(t *testing.T) {
	forEachBackend(t, func(t *testing.T, kind, dsn string) {
		p := open(t, kind, dsn)
		conn, err := p.DB().Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if kind == "sqlite" {
			if err := p.CheckAuditProtected(context.Background(), conn); err != nil {
				t.Fatal(err)
			}
			return
		}
		// the owner/superuser used to run migrations must be refused as the app role
		if err := p.CheckAuditProtected(context.Background(), conn); err == nil {
			t.Fatal("an owner connection must be refused")
		}
		if _, err := conn.ExecContext(context.Background(), `SET ROLE kuukura_app`); err != nil {
			t.Fatal(err)
		}
		if err := p.CheckAuditProtected(context.Background(), conn); err != nil {
			t.Fatalf("the app role is fine: %v", err)
		}
	})
}
