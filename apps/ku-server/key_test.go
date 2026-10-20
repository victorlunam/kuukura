package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/victorlunam/kuukura/internal/access"
	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/keys"
	"github.com/victorlunam/kuukura/internal/masterkey"
	"github.com/victorlunam/kuukura/internal/secrets"
	"github.com/victorlunam/kuukura/internal/storage"
)

func asTerminal(t *testing.T, is bool) {
	old := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return is }
	t.Cleanup(func() { stdoutIsTerminal = old })
}

func TestKeyInitWritesOnlyTheKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "keys", "master_key")
	out := mustRun(t, "key", "init", "--key-file", keyFile)
	want := "This file is your master key. Once the server runs, run `ku-server key show` once and store the key in your password manager.\n"
	if out != want {
		t.Fatalf("no other output: %q", out)
	}
	st, err := os.Stat(keyFile)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", st, err)
	}
	if entries, _ := os.ReadDir(filepath.Dir(keyFile)); len(entries) != 1 {
		t.Fatalf("only the key file is written: %v", entries)
	}
	body, _ := os.ReadFile(keyFile)
	if m, err := keys.ParseMasterKeys(body); err != nil || m.Version() != 1 {
		t.Fatalf("%v", err)
	}
	if strings.Contains(out, strings.TrimSpace(string(body))) {
		t.Fatal("the key is never printed by init")
	}
	if _, err := runOut(t, "key", "init", "--key-file", keyFile); err == nil {
		t.Fatal("init must never overwrite an existing key")
	}
	// the key file defaults to VAULT_MASTER_KEY_FILE
	t.Setenv("VAULT_MASTER_KEY_FILE", filepath.Join(dir, "other"))
	mustRun(t, "key", "init")
	if _, err := os.Stat(filepath.Join(dir, "other")); err != nil {
		t.Fatal(err)
	}
}

// keyFileEnv points the server at a fresh key file holding a version-1 key and returns its path.
func keyFileEnv(t *testing.T) string {
	serverEnv(t)
	path := filepath.Join(t.TempDir(), "keys", "master_key")
	mustRun(t, "key", "init", "--key-file", path)
	t.Setenv("VAULT_MASTER_KEY", "")
	t.Setenv("VAULT_MASTER_KEY_FILE", path)
	return path
}

// seedSecret stores one secret under the key the environment names.
func seedSecret(t *testing.T, p storage.Provider, kp keys.KeyProvider) access.Actor {
	t.Helper()
	ctx := t.Context()
	mustRun(t, "user", "invite", "root@example.test", "--admin")
	if _, err := p.DB().Exec(`UPDATE principals SET status = 'active' WHERE name = 'root@example.test'`); err != nil {
		t.Fatal(err)
	}
	var admin access.Actor
	if err := p.DB().QueryRow(`SELECT id FROM principals WHERE name = 'root@example.test'`).Scan(&admin.ID); err != nil {
		t.Fatal(err)
	}
	log := audit.New(p)
	if err := access.NewAdmin(p, log).Grant(ctx, admin, "root@example.test", "write", []string{"app:shop"}); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.New(p, kp, log).Set(ctx, admin, secrets.SetInput{Name: "ROT", Tags: []string{"app:shop"}, Value: []byte("sk_test_FAKE_EXAMPLE"), Create: true}); err != nil {
		t.Fatal(err)
	}
	return admin
}

func TestKeyShowOncePerVersion(t *testing.T) {
	path := keyFileEnv(t)
	asTerminal(t, false)
	if out, err := runOut(t, "key", "show"); err == nil || out != "" || !strings.Contains(err.Error(), "interactive terminal") || !strings.Contains(err.Error(), "docker exec -it") {
		t.Fatalf("no terminal, no key: %q %v", out, err)
	}
	p := openTest(t)
	if n := count(t, p, `SELECT COUNT(*) FROM audit_log WHERE action = 'read' AND target_type = 'key'`); n != 0 {
		t.Fatal("a refusal reveals nothing and records nothing")
	}

	asTerminal(t, true)
	v1, _ := os.ReadFile(path)
	out := mustRun(t, "key", "show")
	if !strings.Contains(out, strings.TrimSpace(string(v1))) || !strings.Contains(out, "password manager") || !strings.Contains(out, "will not be shown again") ||
		!strings.Contains(out, "age, gpg, sops") {
		t.Fatalf("the key and short instructions: %q", out)
	}
	if n := count(t, p, `SELECT COUNT(*) FROM audit_log a JOIN principals pr ON pr.id = a.principal_id WHERE a.action = 'read' AND a.target_type = 'key' AND pr.name = 'ku-server' AND a.metadata LIKE '%manual:v1%'`); n != 1 {
		t.Fatalf("the reveal is recorded with its key id: %d", n)
	}
	out, err := runOut(t, "key", "show")
	if err == nil || out != "" || !strings.Contains(err.Error(), "already shown on "+nowDay()) || !strings.Contains(err.Error(), path) || strings.Contains(err.Error(), strings.TrimSpace(string(v1))) {
		t.Fatalf("refused the second time, naming the file: %q %v", out, err)
	}

	// rotate: version 2 can be shown once; showing version 1 again stays refused
	mustRun(t, "key", "rotate")
	out = mustRun(t, "key", "show")
	v2, _ := os.ReadFile(path)
	if !strings.Contains(out, strings.TrimSpace(string(v2))) || !strings.Contains(out, "2:") {
		t.Fatalf("the ring with the new version: %q", out)
	}
	if _, err := runOut(t, "key", "show"); err == nil {
		t.Fatal("version 2 is shown once as well")
	}
	if n := count(t, p, `SELECT COUNT(*) FROM audit_log WHERE action = 'read' AND target_type = 'key'`); n != 2 {
		t.Fatalf("one reveal per version: %d", n)
	}
	body, _ := os.ReadFile(path)
	ring, _ := keys.ParseMasterKeys(body)
	log := audit.New(p)
	if _, shown, _ := masterkey.RevealedAt(t.Context(), log, "manual:v1"); !shown {
		t.Fatal("version 1 stays recorded as shown")
	}
	if _, shown, _ := masterkey.RevealedAt(t.Context(), log, ring.KeyID()); !shown {
		t.Fatal("version 2 recorded")
	}

	// aws-kms: the key never leaves KMS
	t.Setenv("VAULT_KEY_PROVIDER", "aws-kms")
	t.Setenv("VAULT_KMS_KEY_ARN", "arn:aws:kms:eu-west-1:111122223333:key/fake")
	if out := mustRun(t, "key", "show"); !strings.Contains(out, "Not applicable: the key never leaves KMS.") {
		t.Fatal(out)
	}
}

func nowDay() string { return time.Now().UTC().Format(time.DateOnly) }

func count(t *testing.T, p storage.Provider, q string) int {
	t.Helper()
	var n int
	if err := p.DB().QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestBackupWarning(t *testing.T) {
	path := keyFileEnv(t)
	ctx := t.Context()
	asTerminal(t, true)
	p := openTest(t)
	a := newApp(mustConfig(t), p)
	kp := func() keys.KeyProvider {
		t.Helper()
		k, err := keyProvider(ctx, mustConfig(t))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}

	if w, err := backupWarning(ctx, a, kp(), false); err != nil || !strings.Contains(w, "manual:v1") || !strings.Contains(w, "ku-server key show") {
		t.Fatalf("an init-created key that was never shown: %q %v", w, err)
	}
	if w, _ := backupWarning(ctx, a, kp(), true); !strings.HasPrefix(w, "generated a new master key at "+path+"; it has no offline copy yet: run `ku-server key show` once and store the key in your password manager") {
		t.Fatalf("%q", w)
	}
	body, _ := os.ReadFile(path)
	if w, _ := backupWarning(ctx, a, kp(), true); strings.Contains(w, strings.TrimSpace(string(body))) {
		t.Fatal("the warning never carries the key")
	}
	mustRun(t, "key", "show")
	if w, err := backupWarning(ctx, a, kp(), false); err != nil || w != "" {
		t.Fatalf("shown keys do not warn: %q %v", w, err)
	}
	mustRun(t, "key", "rotate")
	if w, _ := backupWarning(ctx, a, kp(), false); !strings.Contains(w, "manual:v2") {
		t.Fatalf("a rotated key warns until it is shown: %q", w)
	}
	mustRun(t, "key", "show")
	if w, _ := backupWarning(ctx, a, kp(), false); w != "" {
		t.Fatal(w)
	}
	a.c.KeyProvider = "aws-kms"
	if w, _ := backupWarning(ctx, a, kp(), false); w != "" {
		t.Fatal("aws-kms has no key to back up")
	}
}

func mustConfig(t *testing.T) config {
	t.Helper()
	c, err := loadConfig(false)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestKeyRotateRewrapsInOneTransaction(t *testing.T) {
	path := keyFileEnv(t)
	ctx := t.Context()
	p := openTest(t)
	body1, _ := os.ReadFile(path)
	kp1, _ := keys.ParseMasterKeys(body1)
	admin := seedSecret(t, p, kp1)

	out := mustRun(t, "key", "rotate")
	for _, want := range []string{"Rewrapped 1 secret versions and 0 TOTP secrets to manual:v2", "Restart the server", "Run `ku-server key show` to back up the new key version."} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
	body2, _ := os.ReadFile(path)
	kp2, err := keys.ParseMasterKeys(body2)
	if err != nil || kp2.Version() != 2 || !strings.HasPrefix(string(body2), strings.TrimSpace(string(body1))) {
		t.Fatalf("the file keeps version 1 and gains version 2: %v", err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if _, err := os.Stat(path + ".new"); err == nil {
		t.Fatal("no leftover sibling")
	}
	if n := count(t, p, `SELECT COUNT(*) FROM secret_versions WHERE key_id = 'manual:v2'`); n != 1 {
		t.Fatal("the secret must be on the new key")
	}
	if n := count(t, p, `SELECT COUNT(*) FROM audit_log a JOIN principals pr ON pr.id = a.principal_id WHERE a.action = 'key_rotate' AND pr.name = 'ku-server' AND a.result = 'ok'`); n != 1 {
		t.Fatalf("one key_rotate row under the host principal: %d", n)
	}
	if v, err := secrets.New(p, kp2, audit.New(p)).Reveal(ctx, admin, secrets.Selector{Name: "ROT"}, true); err != nil || string(v.Data) != "sk_test_FAKE_EXAMPLE" {
		t.Fatalf("the value must survive the rotation: %v", err)
	}
	if out := mustRun(t, "key", "rotate", "--rewrap-only"); !strings.Contains(out, "Rewrapped 0 secret versions") {
		t.Fatalf("rewrap-only adds no version and finds nothing left: %q", out)
	}
	if b, _ := os.ReadFile(path); string(b) != string(body2) {
		t.Fatal("--rewrap-only must not change the key file")
	}
	if err := audit.New(p).Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

// With the key in an environment variable or a read-only file, rotate explains the manual two-step path instead,
// and changes nothing.
func TestKeyRotateManualPath(t *testing.T) {
	serverEnv(t)
	p := openTest(t)
	kp1, _ := keys.ParseMasterKeys([]byte(os.Getenv("VAULT_MASTER_KEY")))
	seedSecret(t, p, kp1)
	_, err := runOut(t, "key", "rotate")
	if err == nil || strings.Contains(err.Error(), "\n") || strings.Contains(err.Error(), strings.TrimSpace(os.Getenv("VAULT_MASTER_KEY"))) {
		t.Fatalf("env key: %v", err)
	}
	for _, want := range []string{"2:", "--rewrap-only", "restart"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the manual path names %q: %v", want, err)
		}
	}
	if n := count(t, p, `SELECT COUNT(*) FROM secret_versions WHERE key_id = 'manual:v1'`); n != 1 {
		t.Fatal("nothing changed")
	}

	// the operator adds version 2 where the key lives (here: a bare key becomes a ring), restarts, and rewraps
	k2, _ := keys.GenerateMasterKey(2)
	t.Setenv("VAULT_MASTER_KEY", string(kp1.Ring())+string(k2))
	if out := mustRun(t, "key", "rotate", "--rewrap-only"); !strings.Contains(out, "Rewrapped 1 secret versions and 0 TOTP secrets to manual:v2") {
		t.Fatal(out)
	}

	// a read-only key file is the same case
	path := keyFileEnv(t)
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if _, err := runOut(t, "key", "rotate"); err == nil || !strings.Contains(err.Error(), "--rewrap-only") {
		t.Fatalf("read-only file: %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("a read-only file stays as it is")
	}
}

// A bare key from an environment variable can be rotated by hand: the ring text `key show` prints is the form
// to paste back.
func TestBareKeyRotatesThroughTheRing(t *testing.T) {
	path := keyFileEnv(t)
	body, _ := os.ReadFile(path)
	m, _ := keys.ParseMasterKeys(body)
	bare := strings.TrimPrefix(strings.TrimSpace(string(m.Ring())), "1:")
	if err := os.WriteFile(path, []byte(bare+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "key", "rotate")
	after, _ := os.ReadFile(path)
	ring, err := keys.ParseMasterKeys(after)
	if err != nil || ring.Version() != 2 || !strings.HasPrefix(string(after), "1:"+bare) {
		t.Fatalf("a bare key becomes version 1 of the ring: %v", err)
	}
}

func TestGenerateKey(t *testing.T) {
	serverEnv(t)
	keyFile := filepath.Join(t.TempDir(), "keys", "master_key")
	t.Setenv("VAULT_MASTER_KEY", "")
	t.Setenv("VAULT_MASTER_KEY_FILE", keyFile)
	t.Setenv("VAULT_MASTER_KEY_GENERATE", "true")
	ctx := t.Context()
	p := openTest(t)
	a := newApp(mustConfig(t), p)
	if !a.c.KeyMissing {
		t.Fatal("the file is missing")
	}
	if err := generateKey(ctx, a); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Dir(keyFile)); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("directory 0700: %v %v", st, err)
	}
	if st, err := os.Stat(keyFile); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("file 0600: %v %v", st, err)
	}
	body, _ := os.ReadFile(keyFile)
	if m, err := keys.ParseMasterKeys(body); err != nil || m.Version() != 1 || string(a.c.MasterKey) != string(body) {
		t.Fatalf("%v", err)
	}
	if n := count(t, p, `SELECT COUNT(*) FROM audit_log a JOIN principals pr ON pr.id = a.principal_id WHERE a.action = 'create' AND a.target_type = 'key' AND pr.name = 'ku-server' AND a.metadata LIKE '%manual:v1%'`); n != 1 {
		t.Fatalf("generation is audited without the key: %d", n)
	}
	if c := mustConfig(t); c.KeyMissing || string(c.MasterKey) != string(body) {
		t.Fatal("the next start reuses the file")
	}
	if err := generateKey(ctx, a); err == nil {
		t.Fatal("O_EXCL: never over an existing file")
	}
}

// A key file lost while the database holds encrypted data is never replaced by a fresh key.
func TestGenerateRefusesOverEncryptedData(t *testing.T) {
	path := keyFileEnv(t)
	p := openTest(t)
	body, _ := os.ReadFile(path)
	kp, _ := keys.ParseMasterKeys(body)
	seedSecret(t, p, kp)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_MASTER_KEY_GENERATE", "true")
	a := newApp(mustConfig(t), p)
	err := generateKey(context.Background(), a)
	want := "the master key file " + path + " is missing but the database holds encrypted data; restore the key from your backup"
	if err == nil || err.Error() != want {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("no key may be generated")
	}
}
