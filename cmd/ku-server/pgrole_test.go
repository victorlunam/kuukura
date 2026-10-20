package main

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/access"
	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/auth"
	"github.com/victorlunam/kuukura/identity"
	"github.com/victorlunam/kuukura/keys"
	"github.com/victorlunam/kuukura/secrets"
	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

// The real deployment shape: the app connects with the least privilege its backend offers, and everything it
// does must work while the audit log stays insert-only. On Postgres that is a login role that is only a member
// of kuukura_app, with the tables owned by another role (migrations); on sqlite the tables are protected by
// triggers and the same app flow runs against the file.
func TestAppRunsWithoutAuditWriteAccess(t *testing.T) {
	storagetest.EachDSN(t, func(t *testing.T, kind, dsn string) {
		ctx := t.Context()
		t.Setenv("VAULT_DOMAIN", "vault.example.test")
		kf, _ := keys.GenerateMasterKey(1)
		t.Setenv("VAULT_MASTER_KEY", string(kf))
		kp, err := keys.ParseMasterKeys(kf)
		if err != nil {
			t.Fatal(err)
		}

		var p storage.Provider
		var refusal string // what a refused change to audit_log says on this backend
		if kind == "sqlite" {
			t.Setenv("VAULT_STORAGE", "sqlite")
			t.Setenv("VAULT_SQLITE_PATH", dsn)
			c, err := loadConfig(false)
			if err != nil {
				t.Fatal(err)
			}
			if p, err = openStorage(ctx, c); err != nil {
				t.Fatal(err)
			}
			refusal = "insert-only"
		} else {
			t.Setenv("VAULT_STORAGE", "postgres")
			// first start with the owner URL creates the schema and the kuukura_app group role
			t.Setenv("VAULT_DATABASE_URL", dsn)
			c, err := loadConfig(false)
			if err != nil {
				t.Fatal(err)
			}
			p0, err := openStorage(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			if err := p0.CheckAuditProtected(ctx, p0.DB()); err == nil {
				t.Fatal("running as the table owner must be refused")
			}
			p0.Close()

			ap, err := storage.Open(ctx, "postgres", os.Getenv("VAULT_TEST_POSTGRES_URL"))
			if err != nil {
				t.Fatal(err)
			}
			defer ap.Close()
			login := "kt_login_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
			if _, err := ap.DB().Exec("CREATE ROLE " + login + " LOGIN PASSWORD 'fake-test-pass' IN ROLE kuukura_app"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _, _ = ap.DB().Exec("DROP ROLE IF EXISTS " + login) })
			loginURL, _ := url.Parse(dsn)
			loginURL.User = url.UserPassword(login, "fake-test-pass")
			t.Setenv("VAULT_MIGRATE_DATABASE_URL", dsn)
			t.Setenv("VAULT_DATABASE_URL", loginURL.String())
			c, err = loadConfig(false)
			if err != nil {
				t.Fatal(err)
			}
			if p, err = openStorage(ctx, c); err != nil {
				t.Fatal(err)
			}
			refusal = "permission denied"
		}
		defer p.Close()
		if err := p.CheckAuditProtected(ctx, p.DB()); err != nil {
			t.Fatalf("the app role must pass: %v", err)
		}

		// the whole app works with only the app's privileges
		log, tokens := audit.New(p), auth.NewTokens(p)
		ids := identity.New(p, log, tokens)
		if _, err := ids.BootstrapAdmin(ctx, "root@example.test"); err != nil {
			t.Fatal(err)
		}
		var adminID uuid.UUID
		if _, err := p.DB().Exec(p.Rebind(`UPDATE principals SET status = 'active' WHERE name = ?`), "root@example.test"); err != nil {
			t.Fatal(err)
		}
		if err := p.DB().QueryRow(p.Rebind(`SELECT id FROM principals WHERE name = ?`), "root@example.test").Scan(&adminID); err != nil {
			t.Fatal(err)
		}
		a := access.Actor{ID: adminID}
		ad := access.NewAdmin(p, log)
		if err := ad.Grant(ctx, a, "root@example.test", "write", []string{"app:shop"}); err != nil {
			t.Fatal(err)
		}
		if err := ad.SetMembers(ctx, a, "pay", []string{"root@example.test"}, nil); err != nil {
			t.Fatal(err)
		}
		if err := ad.SetMembers(ctx, a, "pay", nil, []string{"root@example.test"}); err != nil {
			t.Fatal(err)
		}
		if err := ad.Ungrant(ctx, a, "root@example.test", []string{"app:shop"}); err != nil {
			t.Fatal(err)
		}
		if err := ad.Grant(ctx, a, "root@example.test", "write", []string{"app:shop"}); err != nil {
			t.Fatal(err)
		}
		sv := secrets.New(p, kp, log)
		if _, err := sv.Set(ctx, a, secrets.SetInput{Name: "K", Tags: []string{"app:shop"}, Value: []byte("fake"), Create: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := sv.Update(ctx, a, secrets.Selector{Name: "K"}, secrets.Change{AddTags: []string{"env:dev"}}, false); err != nil {
			t.Fatal(err)
		}
		if _, err := sv.Revoke(ctx, a, secrets.Selector{Name: "K"}); err != nil {
			t.Fatal(err)
		}
		if _, err := sv.Archive(ctx, a, secrets.Selector{Name: "K"}); err != nil {
			t.Fatal(err)
		}
		if n, err := sv.RewrapAll(ctx, adminID, 0); err != nil || n != 0 {
			t.Fatalf("rewrap: %d %v", n, err)
		}
		if err := ids.Disable(ctx, a, "root@example.test"); err == nil {
			t.Fatal("last admin")
		}
		if err := log.Verify(ctx); err != nil {
			t.Fatal(err)
		}
		// audit is insert-only for the app
		for _, q := range []string{`UPDATE audit_log SET result = 'ok'`, `DELETE FROM audit_log`} {
			if _, err := p.DB().Exec(q); err == nil || !strings.Contains(err.Error(), refusal) {
				t.Fatalf("%s must be refused (%q): %v", q, refusal, err)
			}
		}
		if kind == "postgres" {
			if _, err := p.DB().Exec(`TRUNCATE audit_log`); err == nil {
				t.Fatal("TRUNCATE audit_log must be denied")
			}
		}
	})
}
