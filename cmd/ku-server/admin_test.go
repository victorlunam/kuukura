package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/access"
	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/keys"
	"github.com/victorlunam/kuukura/secrets"
	"github.com/victorlunam/kuukura/storage"
)

// serverEnv is a complete sqlite configuration; everything else a developer's shell or CI might have set is
// cleared so a test only sees what it sets.
func serverEnv(t *testing.T) {
	kf, _ := keys.GenerateMasterKey(1)
	for _, k := range []string{"VAULT_ADDR", "VAULT_DEV_HTTP", "VAULT_NAME", "VAULT_DATABASE_URL", "VAULT_MIGRATE_DATABASE_URL",
		"VAULT_KMS_KEY_ARN", "VAULT_OIDC_CLIENT_ID", "VAULT_OIDC_CLIENT_SECRET", "VAULT_OIDC_CLIENT_SECRET_FILE"} {
		t.Setenv(k, "")
	}
	t.Setenv("VAULT_DOMAIN", "vault.example.test")
	t.Setenv("VAULT_STORAGE", "sqlite")
	t.Setenv("VAULT_SQLITE_PATH", filepath.Join(t.TempDir(), "k.db"))
	t.Setenv("VAULT_MASTER_KEY", string(kf))
	t.Setenv("VAULT_KEY_PROVIDER", "")
	t.Setenv("VAULT_MASTER_KEY_FILE", "")
}

// openTest opens the storage the environment names, migrated, as the commands do.
func openTest(t *testing.T) storage.Provider {
	t.Helper()
	c, err := loadConfig(false)
	if err != nil {
		t.Fatal(err)
	}
	p, err := openStorage(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func capture(t *testing.T, fn func() error) (string, error) {
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	err := fn()
	os.Stdout = old
	_ = w.Close()
	b, _ := io.ReadAll(r)
	return string(b), err
}

func TestConfigFailsFast(t *testing.T) {
	for _, k := range []string{"VAULT_DOMAIN", "VAULT_STORAGE", "VAULT_SQLITE_PATH", "VAULT_DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_MASTER_KEY_FILE", "VAULT_KEY_PROVIDER", "VAULT_KMS_KEY_ARN"} {
		t.Setenv(k, "")
	}
	if _, err := loadConfig(false); err == nil {
		t.Fatal("an empty environment must be rejected")
	}
	serverEnv(t)
	if _, err := loadConfig(false); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_MASTER_KEY", "")
	_, err := loadConfig(false)
	if err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("the server must refuse to start without the master key: %v", err)
	}
	serverEnv(t)
	t.Setenv("VAULT_STORAGE", "mysql")
	if _, err := loadConfig(false); err == nil {
		t.Fatal("unknown storage")
	}
	serverEnv(t)
	if _, err := loadConfig(true); err == nil {
		t.Fatal("serving needs the OIDC client")
	}
}

func TestAdminInviteAndRotate(t *testing.T) {
	serverEnv(t)
	out, err := capture(t, func() error { return run([]string{"admin", "invite", "--email", "root@example.test"}) })
	if err != nil || !strings.Contains(out, "https://vault.example.test/invite?token=ku_") {
		t.Fatalf("%q %v", out, err)
	}
	if !regexp.MustCompile(`valid until \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\)`).MatchString(out) {
		t.Fatalf("the expiry is an RFC 3339 UTC time, not a local clock time: %q", out)
	}
	// rotate with an unknown admin is refused
	if _, err := capture(t, func() error { return run([]string{"admin", "rotate-key", "--admin", "nobody@example.test"}) }); err == nil {
		t.Fatal("rotate needs an active admin")
	}
	// ... and so is an invited admin who has not signed in yet
	if _, err := capture(t, func() error { return run([]string{"admin", "rotate-key", "--admin", "root@example.test"}) }); err == nil {
		t.Fatal("rotate needs an active admin")
	}
	if _, err := capture(t, func() error { return run([]string{"admin", "invite"}) }); err == nil {
		t.Fatal("email is required")
	}
}

func TestAdminRotateKey(t *testing.T) {
	serverEnv(t)
	ctx := t.Context()
	if _, err := capture(t, func() error { return run([]string{"admin", "invite", "--email", "root@example.test"}) }); err != nil {
		t.Fatal(err)
	}
	p := openTest(t)
	if _, err := p.DB().Exec(`UPDATE principals SET status = 'active' WHERE name = 'root@example.test'`); err != nil {
		t.Fatal(err)
	}
	var adminID uuid.UUID
	if err := p.DB().QueryRow(`SELECT id FROM principals WHERE name = 'root@example.test'`).Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	kf1 := []byte(os.Getenv("VAULT_MASTER_KEY"))
	kp1, err := keys.ParseMasterKeys(kf1)
	if err != nil {
		t.Fatal(err)
	}
	log := audit.New(p)
	admin := access.Actor{ID: adminID}
	if err := access.NewAdmin(p, log).Grant(ctx, admin, "root@example.test", "write", []string{"app:shop"}); err != nil {
		t.Fatal(err)
	}
	const fake = "sk_test_FAKE_EXAMPLE"
	if _, err := secrets.New(p, kp1, log).Set(ctx, admin, secrets.SetInput{Name: "ROT", Tags: []string{"app:shop"}, Value: []byte(fake), Create: true}); err != nil {
		t.Fatal(err)
	}

	// the new key version joins the ring, then the rotation runs with it
	k2, _ := keys.GenerateMasterKey(2)
	t.Setenv("VAULT_MASTER_KEY", string(kf1)+string(k2))
	out, err := capture(t, func() error { return run([]string{"admin", "rotate-key", "--admin", "root@example.test"}) })
	if err != nil || !strings.Contains(out, "Rewrapped 1 secret versions and 0 TOTP secrets to manual:v2") {
		t.Fatalf("%q %v", out, err)
	}
	var keyID string
	if err := p.DB().QueryRow(`SELECT key_id FROM secret_versions`).Scan(&keyID); err != nil || keyID != "manual:v2" {
		t.Fatalf("the secret must be on the new key: %q %v", keyID, err)
	}
	var n int
	if err := p.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'key_rotate' AND principal_id = ? AND result = 'ok'`, adminID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("one key_rotate row for the admin: %d %v", n, err)
	}
	ring, _ := keys.ParseMasterKeys([]byte(os.Getenv("VAULT_MASTER_KEY")))
	if v, err := secrets.New(p, ring, log).Reveal(ctx, admin, secrets.Selector{Name: "ROT"}, true); err != nil || string(v.Data) != fake {
		t.Fatalf("the value must survive the rotation: %v", err)
	}
	if err := log.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestAdminVerifyAudit(t *testing.T) {
	serverEnv(t)
	for range 3 {
		if _, err := capture(t, func() error { return run([]string{"admin", "invite", "--email", "root@example.test"}) }); err != nil {
			t.Fatal(err)
		}
	}
	p := openTest(t)
	var head []byte
	if err := p.DB().QueryRow(`SELECT hash FROM audit_log ORDER BY at DESC LIMIT 1`).Scan(&head); err != nil {
		t.Fatal(err)
	}
	out, err := capture(t, func() error { return run([]string{"admin", "verify-audit"}) })
	if want := fmt.Sprintf("OK: audit log verified, 3 rows, head %x", head); err != nil || strings.TrimSpace(out) != want {
		t.Fatalf("got %q %v, want %q", out, err, want)
	}

	// an edit by someone with direct database access: the command fails
	if _, err := p.DB().Exec(`DROP TRIGGER audit_log_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.DB().Exec(`UPDATE audit_log SET action = 'login' WHERE rowid = (SELECT MIN(rowid) FROM audit_log)`); err != nil {
		t.Fatal(err)
	}
	out, err = capture(t, func() error { return run([]string{"admin", "verify-audit"}) })
	if err == nil || !strings.Contains(err.Error(), "does not verify") || strings.Contains(out, "OK") {
		t.Fatalf("a tampered log must fail: %q %v", out, err)
	}
	if _, err := capture(t, func() error { return run([]string{"admin", "verify-audit", "extra"}) }); err == nil {
		t.Fatal("no arguments")
	}
}

// The cause belongs in the message, the connection credentials do not.
func TestStartupErrorsNameTheCause(t *testing.T) {
	serverEnv(t)
	t.Setenv("VAULT_SQLITE_PATH", filepath.Join(t.TempDir(), "missing-dir", "k.db"))
	c, err := loadConfig(false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = openStorage(t.Context(), c)
	if err == nil || !strings.HasPrefix(err.Error(), "migrations failed: ") || len(err.Error()) <= len("migrations failed: ") {
		t.Fatalf("the cause must follow: %v", err)
	}

	const pw = "fake-pass-9f3a"
	t.Setenv("VAULT_STORAGE", "postgres")
	t.Setenv("VAULT_DATABASE_URL", "postgres://app:"+pw+"@127.0.0.1:1/kuukura?sslmode=disable&connect_timeout=2")
	t.Setenv("VAULT_MIGRATE_DATABASE_URL", "postgres://owner:"+pw+"@127.0.0.1:1/kuukura?sslmode=disable&connect_timeout=2")
	if c, err = loadConfig(false); err != nil {
		t.Fatal(err)
	}
	_, err = openStorage(t.Context(), c)
	if err == nil || !strings.Contains(err.Error(), "migrations failed: ") || strings.Contains(err.Error(), pw) {
		t.Fatalf("a failed connection must say why and not print the password: %v", err)
	}
	if got := c.scrub(errors.New("dial " + c.DatabaseURL + " failed for " + pw)); strings.Contains(got, pw) || strings.Contains(got, "postgres://") {
		t.Fatalf("scrub left credentials: %q", got)
	}

	if _, err := keyProvider(t.Context(), config{KeyProvider: "manual", MasterKey: []byte("1:short")}); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("a bad key file names the line: %v", err)
	}
}

func TestInitAndRotateKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyFile, export1, export2 := filepath.Join(dir, "master_key"), filepath.Join(dir, "v1.age"), filepath.Join(dir, "v2.age")
	promptPass = func() (string, error) { return "correct horse battery", nil }
	t.Cleanup(func() { promptPass = promptPassphrase })

	if err := runInit([]string{"--key-file", keyFile, "--export", export1}); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(keyFile)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v", st.Mode())
	}
	body, _ := os.ReadFile(keyFile)
	m, err := keys.ParseMasterKeys(body)
	if err != nil || m.Version() != 1 {
		t.Fatalf("v1: %v", err)
	}
	if err := runInit([]string{"--key-file", keyFile, "--export", filepath.Join(dir, "again.age")}); err == nil {
		t.Fatal("init must never overwrite an existing key")
	}
	// the offline copy decrypts to the same key file
	f, _ := os.Open(export1)
	defer f.Close()
	ident, err := age.NewScryptIdentity("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	dec, err := age.Decrypt(f, ident)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(dec); string(got) != string(body) {
		t.Fatal("offline copy must hold the key file")
	}

	if err := runInit([]string{"--key-file", keyFile, "--export", export2, "--rotate"}); err != nil {
		t.Fatal(err)
	}
	body2, _ := os.ReadFile(keyFile)
	m2, err := keys.ParseMasterKeys(body2)
	if err != nil || m2.Version() != 2 || !strings.HasPrefix(string(body2), string(body)) {
		t.Fatalf("rotate must keep v1 and add v2: %v", err)
	}
}

func TestDevHTTPOnlyOnLocalhost(t *testing.T) {
	serverEnv(t)
	t.Setenv("VAULT_DEV_HTTP", "true")
	if _, err := loadConfig(false); err == nil {
		t.Fatal("plain HTTP must be refused for a real domain")
	}
	t.Setenv("VAULT_DOMAIN", "localhost")
	t.Setenv("VAULT_ADDR", ":9090")
	c, err := loadConfig(false)
	if err != nil || c.baseURL() != "http://localhost:9090" {
		t.Fatalf("%v %v", c.baseURL(), err)
	}
}
