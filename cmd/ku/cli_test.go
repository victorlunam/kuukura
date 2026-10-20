package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

// passkeyConfirm is the prompt line while the only second step is a passkey.
var passkeyConfirm = "Confirm with " + passkeyLabel(runtime.GOOS) + "... ✓"

func mustOK(t *testing.T, r result) result {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", r.code, r.out, r.errOut)
	}
	return r
}

func noValue(t *testing.T, r result, values ...string) {
	t.Helper()
	for _, v := range values {
		if strings.Contains(r.out, v) || strings.Contains(r.errOut, v) {
			t.Fatalf("a value appeared in CLI output:\nstdout: %s\nstderr: %s", r.out, r.errOut)
		}
	}
}

// userWorld: admin + a member "dev" with write on app:shop, logged in as profile "default".
func userWorld(t *testing.T, p storage.Provider) (*world, string) {
	w := newWorld(t, p)
	admin := w.admin()
	user := w.member(admin, "dev@example.test")
	w.grant(admin, "dev@example.test", "write", "app:shop")
	w.loginAs(user)
	return w, admin
}

func TestCanonicalSecretFlows(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p)

		// set: hidden prompt (TTY), confirm creation
		r := mustOK(t, w.ku("y\n", true, nil, "secret", "set", "DATABASE_URL", "app:shop"))
		if r.out != "" || !strings.Contains(r.errOut, "✓ Saved DATABASE_URL (version 1)\n") || !strings.Contains(r.errOut, "DATABASE_URL is new. Create it? (y/N)") || !strings.Contains(r.errOut, "profile: default") {
			t.Fatalf("set:\n%q\n%q", r.out, r.errOut)
		}
		noValue(t, r, fakeValue)
		if r := w.ku("n\n", true, nil, "secret", "set", "OTHER", "app:shop"); r.code != 1 || !strings.Contains(r.errOut, "Nothing saved.") {
			t.Fatalf("declined: %v", r)
		}
		// piped value, --yes, no terminal
		noValue(t, mustOK(t, w.ku(fakeValue+"\n", false, nil, "secret", "set", "STRIPE_KEY", "app:shop", "env:prod", "team:pay", "--yes")), fakeValue)
		for i := range 3 {
			mustOK(t, w.ku("v"+string(rune('a'+i))+"\n", false, nil, "secret", "set", "STRIPE_KEY", "app:shop", "env:prod", "team:pay", "--yes"))
		}
		if r := w.ku("x\n", false, nil, "secret", "set", "NEW_ONE", "app:shop"); r.code != 1 || !strings.Contains(r.errOut, "--yes") {
			t.Fatalf("piped create needs --yes: %v", r)
		}

		// list: exact table, no values
		r = mustOK(t, w.ku("", false, nil, "secret", "list"))
		want := "NAME              VERSION  TAGS\nDATABASE_URL      1        app:shop\nSTRIPE_KEY        4        app:shop env:prod team:pay\n"
		if r.out != want {
			t.Fatalf("list:\n%q\nwant\n%q", r.out, want)
		}
		noValue(t, r, fakeValue, "va", "vb")

		// get without a choice
		r = w.ku("", false, nil, "secret", "get", "STRIPE_KEY", "env:prod")
		if r.code != 2 || r.errOut != "Usage: "+getUsage+"\n" {
			t.Fatalf("get: %q", r.errOut)
		}
		if w.stepUps != 0 {
			t.Fatal("no confirmation without a choice")
		}

		// reveal: confirmation with the passkey, value on stdout
		mustOK(t, w.ku(fakeValue+"\n", false, nil, "secret", "set", "STRIPE_KEY", "app:shop", "env:prod", "team:pay", "--yes"))
		r = mustOK(t, w.ku("", false, nil, "secret", "get", "STRIPE_KEY", "env:prod", "--reveal"))
		if r.out != fakeValue || !strings.Contains(r.errOut, passkeyConfirm) || w.stepUps != 1 {
			t.Fatalf("reveal: %q %q steps=%d", r.out, r.errOut, w.stepUps)
		}

		// --out: confirmation, file 0600
		out := filepath.Join(t.TempDir(), "key.txt")
		r = mustOK(t, w.ku("", false, nil, "secret", "get", "STRIPE_KEY", "env:prod", "--out", out))
		st, err := os.Stat(out)
		b, _ := os.ReadFile(out)
		if err != nil || st.Mode().Perm() != 0o600 || string(b) != fakeValue || w.stepUps != 2 {
			t.Fatalf("--out: %v %v steps=%d", err, st, w.stepUps)
		}
		noValue(t, r, fakeValue)

		// rename (typo fix)
		mustOK(t, w.ku("v\n", false, nil, "secret", "set", "BASE_ULR", "app:shop", "--yes"))
		r = mustOK(t, w.ku("", false, nil, "secret", "update", "BASE_ULR", "--name", "BASE_URL"))
		if r.out != "" || !strings.HasSuffix(r.errOut, "✓ Renamed BASE_ULR to BASE_URL\n") {
			t.Fatalf("rename: %q %q", r.out, r.errOut)
		}

		// bulk authorize: confirm, then a confirmation for requires_authorize on run
		r = mustOK(t, w.ku("y\n", true, nil, "secret", "update", "env:prod", "team:pay", "--authorize", "on"))
		if !strings.HasSuffix(r.errOut, "✓ Updated STRIPE_KEY\n") || strings.Contains(r.errOut, "Continue?") { // one match: no confirmation
			t.Fatalf("single: %q", r.errOut)
		}
		r = mustOK(t, w.ku("y\n", true, nil, "secret", "update", "app:shop", "--authorize", "on"))
		if !strings.Contains(r.errOut, "  STRIPE_KEY    app:shop env:prod team:pay\n") || !strings.Contains(r.errOut, "3 secrets will ask for a confirmation. Continue? (y/N)") || !strings.HasSuffix(r.errOut, "✓ Updated 3 secrets\n") || r.out != "" {
			t.Fatalf("bulk:\n%q\n%q", r.out, r.errOut)
		}
		if r := w.ku("n\n", true, nil, "secret", "update", "app:shop", "--authorize", "off"); r.code != 1 || w.stepUps != 2 || !strings.Contains(r.errOut, "✗ Nothing changed.") {
			t.Fatalf("declined bulk must not ask for a confirmation: %v steps=%d", r, w.stepUps)
		}

		// clash: exact copy
		mustOK(t, w.ku("v\n", false, nil, "secret", "set", "STRIPE_KEY", "app:shop", "env:qa", "team:pay", "--yes"))
		r = w.ku("y\n", true, nil, "secret", "update", "team:pay", "+env:qa")
		wantClash := "✗ 1 of 2 secrets would clash:\n    STRIPE_KEY app:shop env:qa team:pay already exists\n  Nothing changed.\n"
		if r.code != 1 || !strings.HasSuffix(r.errOut, wantClash) {
			t.Fatalf("clash:\n%q", r.errOut)
		}

		// revoke blocks run until the next set
		mustOK(t, w.ku("", false, nil, "secret", "revoke", "STRIPE_KEY", "env:prod"))
		r = w.ku("", false, map[string]string{}, "run", "env:prod", "--", "true")
		if r.code != 1 || !strings.Contains(r.errOut, "✗ STRIPE_KEY is blocked until you save a new value.\n  Run: ku secret set STRIPE_KEY app:shop env:prod team:pay\n") {
			t.Fatalf("blocked:\n%q", r.errOut)
		}

		// archive
		mustOK(t, w.ku("", false, nil, "secret", "archive", "BASE_URL"))
		if r := w.ku("", false, nil, "secret", "list", "BASE_URL"); r.out != "" || !strings.Contains(r.errOut, "No secrets found") {
			t.Fatalf("archived: %q %q", r.out, r.errOut)
		}
	})
}

func TestRun(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p)
		for _, s := range [][]string{{"BASE_URL", "app:shop", "env:dev"}, {"BASE_URL", "app:shop", "env:prod"}, {"API_KEY", "app:shop", "env:dev"}} {
			mustOK(t, w.ku("val-"+s[2]+"\n", false, nil, append([]string{"secret", "set"}, append(s, "--yes")...)...))
		}
		// a file secret
		cert := filepath.Join(t.TempDir(), "tls.pem")
		_ = os.WriteFile(cert, []byte("CERT-FAKE\n"), 0o600)
		mustOK(t, w.ku("", false, nil, "secret", "set", "TLS_CERT", "app:shop", "env:dev", "--file", cert, "--yes"))

		// unlinked and no tags: nothing injected
		marker := filepath.Join(t.TempDir(), "ran")
		r := w.ku("", false, nil, "run", "--", "touch", marker)
		if r.code != 1 || !strings.Contains(r.errOut, "✗ This folder is not linked to an app.\n  Run: ku link <app>   (your apps: shop)") || fileExists(marker) {
			t.Fatalf("unlinked:\n%q", r.errOut)
		}

		// ambiguous: the exact copy and the hint
		r = w.ku("", false, nil, "run", "app:shop", "--", "npm", "run", "dev")
		wantAmb := "✗ 2 secrets are called BASE_URL:\n    BASE_URL  app:shop env:dev\n    BASE_URL  app:shop env:prod\n  Add or remove a tag to pick one, for example: ku run env:dev -- npm run dev\n"
		if r.code != 1 || !strings.HasSuffix(r.errOut, wantAmb) {
			t.Fatalf("ambiguous:\n%q", r.errOut)
		}

		// link the folder, then run injects and cleans up
		work := t.TempDir()
		env := map[string]string{"CWD": work}
		mustOK(t, w.ku("", false, env, "link", "shop"))
		if r := mustOK(t, w.ku("", false, env, "link")); !strings.Contains(r.out, "linked to shop") {
			t.Fatal(r.out)
		}
		script := `echo "key=$API_KEY base=$BASE_URL"; echo "path=$TLS_CERT"; cat "$TLS_CERT"; stat -f %Lp "$TLS_CERT" 2>/dev/null || stat -c %a "$TLS_CERT"`
		r = mustOK(t, w.ku("", false, env, "run", "env:dev", "--", "sh", "-c", script))
		if !strings.Contains(r.out, "key=val-env:dev base=val-env:dev") || !strings.Contains(r.out, "CERT-FAKE") || !strings.Contains(r.out, "\n600\n") {
			t.Fatalf("run output: %q", r.out)
		}
		path := strings.Split(strings.Split(r.out, "path=")[1], "\n")[0]
		if fileExists(path) || fileExists(filepath.Dir(path)) {
			t.Fatal("the temp file must be deleted on exit")
		}
		if w.stepUps != 0 {
			t.Fatal("plain run needs no confirmation")
		}

		// the command's exit code passes through, and files are still cleaned up on failure
		r = w.ku("", false, env, "run", "env:dev", "--", "sh", "-c", `echo "$TLS_CERT" > `+marker+`; exit 7`)
		if r.code != 7 {
			t.Fatalf("exit code: %d", r.code)
		}
		b, _ := os.ReadFile(marker)
		if p := strings.TrimSpace(string(b)); p == "" || fileExists(p) || fileExists(filepath.Dir(p)) {
			t.Fatalf("temp files must be removed when the command fails: %q", p)
		}

		// requires_authorize: a confirmation once per command
		mustOK(t, w.ku("y\n", true, env, "secret", "update", "env:dev", "--authorize", "on", "--yes"))
		r = mustOK(t, w.ku("", false, env, "run", "env:dev", "--", "sh", "-c", `echo $API_KEY`))
		if w.stepUps != 1 || !strings.Contains(r.errOut, passkeyConfirm) || !strings.Contains(r.out, "val-env:dev") {
			t.Fatalf("authorize: steps=%d %q", w.stepUps, r.errOut)
		}
	})
}
