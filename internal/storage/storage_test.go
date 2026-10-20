package storage_test

import (
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

func exec(t *testing.T, p storage.Provider, q string, args ...any) error {
	t.Helper()
	_, err := p.DB().Exec(p.Rebind(q), args...)
	return err
}

func mustExec(t *testing.T, p storage.Provider, q string, args ...any) {
	t.Helper()
	if err := exec(t, p, q, args...); err != nil {
		t.Fatal(err)
	}
}

func newPrincipal(t *testing.T, p storage.Provider) string {
	id := uuid.NewString()
	mustExec(t, p, `INSERT INTO principals (id, kind, name, email, role, status) VALUES (?, 'human', ?, 'a@example.test', 'admin', 'active')`, id, "p-"+id)
	return id
}

func newSecret(t *testing.T, p storage.Provider, by, name string, tags storage.Tags) (string, error) {
	id := uuid.NewString()
	err := exec(t, p, `INSERT INTO secrets (id, name, kind, tags, created_by) VALUES (?, ?, 'text', ?, ?)`, id, name, p.TagsArg(tags), by)
	return id, err
}

func TestMigrationsReversibleWithData(t *testing.T) {
	storagetest.EachDSN(t, func(t *testing.T, kind, dsn string) {
		files, err := fs.ReadDir(storage.Migrations, "migrations/"+kind)
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.Migrate(kind, dsn); err != nil {
			t.Fatal(err)
		}
		p, err := storage.Open(t.Context(), kind, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		m, err := storage.Migrator(kind, dsn)
		if err != nil {
			t.Fatal(err)
		}
		// back to the state before the default-factor migration, then fill it with an account that has two factors
		for range 2 {
			if err := m.Rollback(); err != nil {
				t.Fatal(err)
			}
		}
		by := newPrincipal(t, p)
		older, newer := uuid.NewString(), uuid.NewString()
		base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
		for i, id := range []string{newer, older} { // inserted newest first: the backfill must go by age, not by order
			mustExec(t, p, `INSERT INTO credentials (id, principal_id, kind, public_key, created_at) VALUES (?, ?, 'passkey', ?, ?)`,
				id, by, []byte("fake-key"), p.TimeArg(base.Add(time.Duration(-i)*time.Hour)))
		}
		sid, err := newSecret(t, p, by, "KEPT", storage.Tags{"app:shop"})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Migrate(); err != nil {
			t.Fatal(err)
		}
		isDefault := func(id string) bool {
			var d bool
			if err := p.DB().QueryRow(p.Rebind(`SELECT is_default FROM credentials WHERE id = ?`), id).Scan(&d); err != nil {
				t.Fatal(err)
			}
			return d
		}
		if !isDefault(older) || isDefault(newer) {
			t.Fatal("migrating up must make the oldest factor the default, and only it")
		}
		var n int
		if err := p.DB().QueryRow(p.Rebind(`SELECT COUNT(*) FROM secrets WHERE id = ?`), sid).Scan(&n); err != nil || n != 1 {
			t.Fatalf("existing rows must survive the migration: %d %v", n, err)
		}

		// every migration rolls back, and the schema comes back
		for range files {
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
	got, err := storage.NormalizeTags([]string{"Env:Prod", "app:shop", "env:prod"})
	if err != nil || !slices.Equal(got, storage.Tags{"app:shop", "env:prod"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range [][]string{{"nocolon"}, {"a:b:c"}, {"a:"}, {"A B:c"}} {
		if _, err := storage.NormalizeTags(bad); err == nil {
			t.Fatalf("%v should be rejected", bad)
		}
	}
	many := make([]string, 11)
	for i := range many {
		many[i] = fmt.Sprintf("k:v%d", i)
	}
	if _, err := storage.NormalizeTags(many); err == nil {
		t.Fatal("11 tags should be rejected")
	}
}

// A secret value passed as a tag by mistake must not come back in the error.
func TestRejectedTagIsNotEchoed(t *testing.T) {
	const value = "sk_test_FAKE_EXAMPLE"
	_, err := storage.NormalizeTags([]string{"app:shop", value})
	if err == nil {
		t.Fatal("must be rejected")
	}
	if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(value)) || !strings.Contains(err.Error(), "2") {
		t.Fatalf("the error must name the position, not the input: %v", err)
	}
}

func TestTagsRoundTrip(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		by := newPrincipal(t, p)
		for _, want := range []storage.Tags{{}, {"app:shop"}, {"app:shop", "env:prod", "team:pay"}} {
			id, err := newSecret(t, p, by, "RT_"+strings.ToUpper(strings.NewReplacer(":", "_", "-", "_").Replace(strings.Join(want, "_"))), want)
			if err != nil {
				t.Fatal(err)
			}
			var got storage.Tags
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
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		by := newPrincipal(t, p)
		tags := storage.Tags{"app:shop", "env:prod"}
		id, err := newSecret(t, p, by, "STRIPE_KEY", tags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := newSecret(t, p, by, "STRIPE_KEY", tags); err == nil {
			t.Fatal("duplicate name+tags must be rejected")
		}
		if _, err := newSecret(t, p, by, "STRIPE_KEY", storage.Tags{"app:shop", "env:qa"}); err != nil {
			t.Fatalf("same name, other tags must be allowed: %v", err)
		}
		if _, err := newSecret(t, p, by, "stripe_key", storage.Tags{"app:x"}); err == nil {
			t.Fatal("lowercase name must be rejected by CHECK")
		}
		mustExec(t, p, `UPDATE secrets SET archived_at = ?, archived_by = ? WHERE id = ?`, p.TimeArg(time.Now()), by, id)
		if _, err := newSecret(t, p, by, "STRIPE_KEY", tags); err != nil {
			t.Fatalf("name+tags must be reusable after archive: %v", err)
		}
	})
}

func TestAuditLogInsertOnly(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		by := newPrincipal(t, p)
		ctx := t.Context()
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
		at := p.TimeArg(time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC))
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
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		by := newPrincipal(t, p)
		secrets := map[string]storage.Tags{
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
			sel  storage.Tags
			want []string
		}{
			{storage.Tags{}, []string{"S_NONE", "S_OTHER", "S_PAY", "S_PROD", "S_SHOP"}},
			{storage.Tags{"app:shop"}, []string{"S_PAY", "S_PROD", "S_SHOP"}},
			{storage.Tags{"app:shop", "env:prod"}, []string{"S_PAY", "S_PROD"}},
			{storage.Tags{"env:prod", "team:pay"}, []string{"S_PAY"}},
			{storage.Tags{"env:qa"}, nil},
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
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		conn, err := p.DB().Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if kind == "sqlite" {
			if err := p.CheckAuditProtected(ctx, conn); err != nil {
				t.Fatal(err)
			}
			return
		}
		// the owner/superuser used to run migrations must be refused as the app role
		if err := p.CheckAuditProtected(ctx, conn); err == nil {
			t.Fatal("an owner connection must be refused")
		}
		if _, err := conn.ExecContext(ctx, `SET ROLE kuukura_app`); err != nil {
			t.Fatal(err)
		}
		if err := p.CheckAuditProtected(ctx, conn); err != nil {
			t.Fatalf("the app role is fine: %v", err)
		}
		if _, err := conn.ExecContext(ctx, `RESET ROLE`); err != nil {
			t.Fatal(err)
		}

		// A member of the owner role that does not inherit holds no privilege itself but can SET ROLE to the owner,
		// so the privilege test alone would pass it.
		var owner string
		if err := conn.QueryRowContext(ctx, `SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'audit_log'::regclass`).Scan(&owner); err != nil {
			t.Fatal(err)
		}
		member := "kt_member_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
		if _, err := conn.ExecContext(ctx, `CREATE ROLE `+member+` NOINHERIT IN ROLE kuukura_app, `+owner); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = p.DB().Exec(`DROP ROLE ` + member) })
		if _, err := conn.ExecContext(ctx, `SET ROLE `+member); err != nil {
			t.Fatal(err)
		}
		err = p.CheckAuditProtected(ctx, conn)
		if err == nil || !strings.Contains(err.Error(), "owner") {
			t.Fatalf("a member of the owner role must be refused: %v", err)
		}
	})
}
