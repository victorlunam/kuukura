package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/keys"
	"github.com/victorlunam/kuukura/internal/storage"
)

// serverEnv is a complete sqlite configuration; everything else a developer's shell or CI might have set is
// cleared so a test only sees what it sets.
func serverEnv(t *testing.T) {
	kf, _ := keys.GenerateMasterKey(1)
	for _, k := range []string{"VAULT_ADDR", "VAULT_DEV_HTTP", "VAULT_NAME", "VAULT_DATABASE_URL", "VAULT_MIGRATE_DATABASE_URL",
		"VAULT_KMS_KEY_ARN", "VAULT_OIDC_CLIENT_ID", "VAULT_OIDC_CLIENT_SECRET", "VAULT_OIDC_CLIENT_SECRET_FILE", "VAULT_MASTER_KEY_GENERATE"} {
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
	for _, k := range []string{"VAULT_DOMAIN", "VAULT_STORAGE", "VAULT_SQLITE_PATH", "VAULT_DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_MASTER_KEY_FILE", "VAULT_MASTER_KEY_GENERATE", "VAULT_KEY_PROVIDER", "VAULT_KMS_KEY_ARN"} {
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

func TestTrustedProxiesConfig(t *testing.T) {
	serverEnv(t)
	for in, want := range map[string]int{
		"":                                 0,
		"203.0.113.0/24":                   1,
		"2001:db8::/32, 203.0.113.0/24":    2,
		"cloudflare":                       len(cloudflareRanges),
		"Cloudflare,203.0.113.0/24":        len(cloudflareRanges) + 1,
		" cloudflare , , 198.51.100.0/24 ": len(cloudflareRanges) + 1,
	} {
		t.Setenv("VAULT_TRUSTED_PROXIES", in)
		c, err := loadConfig(false)
		if err != nil || len(c.TrustedProxies) != want {
			t.Errorf("%q: %d ranges, %v; want %d", in, len(c.TrustedProxies), err, want)
		}
	}
	for _, bad := range []string{"203.0.113.0", "203.0.113.0/33", "cloudflare,nope", "cloudflare;203.0.113.0/24"} {
		t.Setenv("VAULT_TRUSTED_PROXIES", bad)
		_, err := loadConfig(false)
		if err == nil || !strings.Contains(err.Error(), "VAULT_TRUSTED_PROXIES") {
			t.Errorf("%q must be rejected naming the variable: %v", bad, err)
		}
	}
	t.Setenv("VAULT_TRUSTED_PROXIES", "cloudflare,nope")
	if _, err := loadConfig(false); err == nil || !strings.Contains(err.Error(), `"nope"`) {
		t.Errorf("the error must name the bad entry: %v", err)
	}
}

// Platforms hand over the domain in whatever shape: https://, a trailing slash, capitals.
func TestDomainIsNormalized(t *testing.T) {
	serverEnv(t)
	for in, want := range map[string]string{
		"vault.example.test":          "vault.example.test",
		"https://Vault.Example.test":  "vault.example.test",
		"https://vault.example.test/": "vault.example.test",
		"http://vault.example.test/":  "vault.example.test",
		" VAULT.example.test ":        "vault.example.test",
	} {
		t.Setenv("VAULT_DOMAIN", in)
		c, err := loadConfig(false)
		if err != nil || c.Domain != want || c.baseURL() != "https://"+want {
			t.Errorf("%q: %q %v", in, c.Domain, err)
		}
	}
	for _, bad := range []string{"https://vault.example.test/path", "vault.example.test/path", "vault.example.test:8080", "two words", "https://", "/"} {
		t.Setenv("VAULT_DOMAIN", bad)
		if _, err := loadConfig(false); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestKeyGenerateConfig(t *testing.T) {
	serverEnv(t)
	keyFile := filepath.Join(t.TempDir(), "keys", "master_key")
	t.Setenv("VAULT_MASTER_KEY", "")
	t.Setenv("VAULT_MASTER_KEY_FILE", keyFile)
	if _, err := loadConfig(false); err == nil {
		t.Fatal("a missing key file is an error without generate mode")
	}
	t.Setenv("VAULT_MASTER_KEY_GENERATE", "true")
	c, err := loadConfig(false)
	if err != nil || !c.KeyMissing || !c.KeyGenerate || c.KeyFile != keyFile {
		t.Fatalf("%+v %v", c, err)
	}
	t.Setenv("VAULT_MASTER_KEY_FILE", "")
	if _, err := loadConfig(false); err == nil {
		t.Fatal("generate mode needs the key file path")
	}
	// an existing file is used as it is, and an empty one is not a key
	t.Setenv("VAULT_MASTER_KEY_FILE", keyFile)
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(false); err == nil {
		t.Fatal("an empty key file must not be replaced by a generated key")
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
