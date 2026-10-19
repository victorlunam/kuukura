package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/keys"
)

func serverEnv(t *testing.T) {
	kf, _ := keys.GenerateMasterKey(1)
	t.Setenv("VAULT_DOMAIN", "vault.example.test")
	t.Setenv("VAULT_STORAGE", "sqlite")
	t.Setenv("VAULT_SQLITE_PATH", filepath.Join(t.TempDir(), "k.db"))
	t.Setenv("VAULT_MASTER_KEY", string(kf))
	t.Setenv("VAULT_KEY_PROVIDER", "")
	t.Setenv("VAULT_MASTER_KEY_FILE", "")
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
	// the master key file takes the same ring format; rotate with an unknown admin is refused
	if _, err := capture(t, func() error { return run([]string{"admin", "rotate-key", "--admin", "nobody@example.test"}) }); err == nil {
		t.Fatal("rotate needs an active admin")
	}
	if _, err := capture(t, func() error { return run([]string{"admin", "invite"}) }); err == nil {
		t.Fatal("email is required")
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
	got, err := keys.ImportMasterKey(f, "correct horse battery")
	_ = f.Close()
	if err != nil || string(got) != string(body) {
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
