package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

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

func TestMachineTokenInCI(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, admin := userWorld(t, p)
		mustOK(t, w.ku("v1\n", false, nil, "secret", "set", "DEPLOY_KEY", "app:shop", "--yes"))
		// the admin owns the machine and has no grants: it can read nothing. Give the admin read access too.
		w.grant(admin, "root@example.test", "read", "app:shop")
		w.loginAs(admin)
		r := mustOK(t, w.ku("", false, nil, "workspace", "invite", "ci-deploy", "--machine"))
		// stdout carries the token and nothing else, so `| pbcopy` copies exactly it
		token := strings.TrimSuffix(r.out, "\n")
		if !strings.HasPrefix(token, "ku_") || strings.ContainsAny(token, " \n") || !strings.Contains(r.errOut, "KU_TOKEN") {
			t.Fatalf("machine invite: %q %q", r.out, r.errOut)
		}
		mustOK(t, w.ku("", false, nil, "workspace", "grant", "ci-deploy", "read", "app:shop"))

		// KU_URL + KU_TOKEN: no config file, no saved session
		home := t.TempDir()
		w.home = home
		env := map[string]string{"KU_URL": w.srv.URL, "KU_TOKEN": token}
		r = mustOK(t, w.ku("", false, env, "run", "app:shop", "--", "sh", "-c", "echo $DEPLOY_KEY"))
		if !strings.Contains(r.out, "v1") || !strings.Contains(r.errOut, "profile: (env)") {
			t.Fatalf("ci run: %q %q", r.out, r.errOut)
		}
		if _, err := os.Stat(filepath.Join(home, ".config")); err == nil {
			t.Fatal("an ephemeral profile writes no config")
		}
		// machines can never reveal
		if r := w.ku("", false, env, "secret", "get", "DEPLOY_KEY", "--reveal"); r.code != 1 || !strings.Contains(r.errOut, "✗ You don't have access to that.") {
			t.Fatalf("machine reveal: %v", r)
		}
		if w.stepUps != 0 {
			t.Fatal("machines never get a step-up")
		}
	})
}

// Someone who can write the secrets of an app must not be able to make a teammate's `ku run` load their code:
// a secret named like a loader or interpreter hook is refused, naming it, and the command never starts.
func TestRunRefusesLoaderAndInterpreterHooks(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p)
		lib := filepath.Join(t.TempDir(), "evil.so")
		if err := os.WriteFile(lib, []byte("FAKE-LIBRARY"), 0o600); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(t.TempDir(), "ran")
		for _, name := range []string{"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "NODE_OPTIONS", "PATH", "PYTHONPATH", "BASH_ENV"} {
			args := []string{"secret", "set", name, "app:shop", "env:hook", "--yes"}
			if name == "LD_PRELOAD" || name == "DYLD_INSERT_LIBRARIES" { // a file secret becomes a path to a library
				args = append(args, "--file", lib)
			}
			mustOK(t, w.ku(fakeValue+"\n", false, nil, args...))
			r := w.ku("", false, nil, "run", name, "env:hook", "--", "touch", marker)
			if r.code != 1 || !strings.Contains(r.errOut, "✗ "+name+" would change how the command loads code") || fileExists(marker) {
				t.Errorf("%s: exit %d, ran=%v\n%s", name, r.code, fileExists(marker), r.errOut)
			}
			noValue(t, r, fakeValue)
		}
		// an ordinary name next to them still works
		mustOK(t, w.ku("v\n", false, nil, "secret", "set", "API_KEY", "app:shop", "env:ok", "--yes"))
		mustOK(t, w.ku("", false, nil, "run", "env:ok", "--", "touch", marker))
		if !fileExists(marker) {
			t.Fatal("a normal secret must be injected")
		}
	})
}
