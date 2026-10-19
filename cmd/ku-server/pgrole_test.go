package main

import (
	"context"
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
)

// The real deployment shape on Postgres: tables owned by one role (migrations), the server connected as a
// login role that is only a member of kuukura_app. Everything the app does must work, audit must stay insert-only.
func TestPostgresNonOwnerAppRole(t *testing.T) {
	if os.Getenv("VAULT_STORAGE") == "sqlite" {
		return // this test is about the Postgres backend only
	}
	admin := os.Getenv("VAULT_TEST_POSTGRES_URL")
	if admin == "" {
		t.Fatal("VAULT_TEST_POSTGRES_URL is required")
	}
	ctx := context.Background()
	ap, err := storage.Open(ctx, "postgres", admin)
	if err != nil {
		t.Fatal(err)
	}
	defer ap.Close()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	dbName, login := "kt_role_"+suffix, "kt_login_"+suffix
	exec := func(q string) {
		t.Helper()
		if _, err := ap.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	exec("CREATE DATABASE " + dbName)
	t.Cleanup(func() {
		_, _ = ap.DB().Exec("DROP DATABASE " + dbName + " WITH (FORCE)")
		_, _ = ap.DB().Exec("DROP ROLE IF EXISTS " + login)
	})

	ownerURL, _ := url.Parse(admin)
	ownerURL.Path = "/" + dbName
	// first start with the owner URL creates the schema and the kuukura_app group role
	t.Setenv("VAULT_STORAGE", "postgres")
	t.Setenv("VAULT_DOMAIN", "vault.example.test")
	t.Setenv("VAULT_DATABASE_URL", ownerURL.String())
	kf, _ := keys.GenerateMasterKey(1)
	t.Setenv("VAULT_MASTER_KEY", string(kf))
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

	exec("CREATE ROLE " + login + " LOGIN PASSWORD 'fake-test-pass' IN ROLE kuukura_app")
	loginURL, _ := url.Parse(admin)
	loginURL.User = url.UserPassword(login, "fake-test-pass")
	loginURL.Path = "/" + dbName
	t.Setenv("VAULT_MIGRATE_DATABASE_URL", ownerURL.String())
	t.Setenv("VAULT_DATABASE_URL", loginURL.String())
	c, err = loadConfig(false)
	if err != nil {
		t.Fatal(err)
	}
	p, err := openStorage(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.CheckAuditProtected(ctx, p.DB()); err != nil {
		t.Fatalf("the app role must pass: %v", err)
	}

	// the whole app works with only the app role's privileges
	kp, _ := keys.ParseMasterKeys(kf)
	log, tokens := audit.New(p), auth.NewTokens(p)
	ids := identity.New(p, log, tokens)
	if _, err := ids.BootstrapAdmin(ctx, "root@example.test"); err != nil {
		t.Fatal(err)
	}
	var adminID uuid.UUID
	if _, err := p.DB().Exec(`UPDATE principals SET status = 'active' WHERE name = 'root@example.test'`); err != nil {
		t.Fatal(err)
	}
	if err := p.DB().QueryRow(`SELECT id FROM principals WHERE name = 'root@example.test'`).Scan(&adminID); err != nil {
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
	if n, err := sv.RewrapAll(ctx); err != nil || n != 0 {
		t.Fatalf("rewrap: %d %v", n, err)
	}
	if err := ids.Disable(ctx, a, "root@example.test"); err == nil {
		t.Fatal("last admin")
	}
	if err := log.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	// audit is insert-only for the app role
	if _, err := p.DB().Exec(`UPDATE audit_log SET result = 'ok'`); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("UPDATE audit_log must be denied: %v", err)
	}
	if _, err := p.DB().Exec(`DELETE FROM audit_log`); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("DELETE audit_log must be denied: %v", err)
	}
	if _, err := p.DB().Exec(`TRUNCATE audit_log`); err == nil {
		t.Fatal("TRUNCATE audit_log must be denied")
	}
}
