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
		// each row says which tag picks it, and the example keeps app:shop: without it the copy would select env:dev
		// of every app
		wantAmb := "✗ 2 secrets are called BASE_URL:\n" +
			"    BASE_URL  app:shop env:dev   add env:dev to pick this one\n" +
			"    BASE_URL  app:shop env:prod  add env:prod to pick this one (also leaves out API_KEY, TLS_CERT)\n" +
			"  For example: ku run app:shop env:dev -- <command>\n"
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

// A monorepo app holds a secret for the api and one for a worker under the same name: a selector that cannot name
// the worker's role used to fail. ~key:value leaves it out, and the ambiguity error suggests it.
func TestExcludeTags(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p)
		mustOK(t, w.ku("api-pw\n", false, nil, "secret", "set", "DB_PASSWORD", "app:shop", "env:dev", "--yes"))
		mustOK(t, w.ku("worker-pw\n", false, nil, "secret", "set", "DB_PASSWORD", "app:shop", "role:cf-worker", "env:dev", "--yes"))
		show := []string{"--", "sh", "-c", "echo $DB_PASSWORD"}

		// ambiguous: each row says which tag picks it (the api's by leaving the role out), and the example repeats
		// what was typed, not the command (its quoting would be lost)
		r := w.ku("", false, nil, append([]string{"run", "app:shop", "env:dev"}, show...)...)
		if r.code != 1 {
			t.Fatalf("ambiguous exit: %d", r.code)
		}
		for _, want := range []string{
			"add ~role:cf-worker to pick this one\n", "add role:cf-worker to pick this one\n",
			"  For example: ku run app:shop env:dev ~role:cf-worker -- <command>\n",
		} {
			if !strings.Contains(r.errOut, want) {
				t.Fatalf("ambiguous, missing %q:\n%s", want, r.errOut)
			}
		}

		// excluding it runs only the api's secret; the worker's is still there for its own selector
		r = mustOK(t, w.ku("", false, nil, append([]string{"run", "app:shop", "env:dev", "~role:cf-worker"}, show...)...))
		if strings.TrimSpace(r.out) != "api-pw" {
			t.Fatalf("run without the worker: %q", r.out)
		}
		r = mustOK(t, w.ku("", false, nil, append([]string{"run", "role:cf-worker", "env:dev"}, show...)...))
		if strings.TrimSpace(r.out) != "worker-pw" {
			t.Fatalf("run of the worker: %q", r.out)
		}

		// list honors it, and so does the audit
		r = mustOK(t, w.ku("", false, nil, "secret", "list", "app:shop", "~role:cf-worker"))
		if strings.Contains(r.out, "role:cf-worker") || !strings.Contains(r.out, "DB_PASSWORD") {
			t.Fatalf("list: %q", r.out)
		}

		// the same tag required and excluded is an error, and set takes no exclusions
		if r := w.ku("", false, nil, "secret", "list", "app:shop", "~app:shop"); r.code != 1 {
			t.Fatalf("required and excluded: %v", r)
		}
		if r := w.ku("v\n", false, nil, "secret", "set", "X_KEY", "app:shop", "~role:cf-worker", "--yes"); r.code != 2 {
			t.Fatalf("set with an exclusion: %v", r)
		}
		// every tag is key:value, an excluded one too, and it is never taken for a name
		for _, bad := range []string{"~role", "~", "~role:", "~:x"} {
			if r := w.ku("", false, nil, "secret", "list", "app:shop", bad); r.code != 2 || !strings.Contains(r.errOut, "is not a tag (key:value)") {
				t.Fatalf("%q: %v", bad, r)
			}
		}
		// grants take no exclusions (they are patterns of the secret's own tags)
		if r := w.ku("", false, nil, "workspace", "grant", "root@example.test", "read", "~role:cf-worker"); r.code == 0 || !strings.Contains(r.errOut, "is not a tag (key:value)") {
			t.Fatalf("a grant with an exclusion must be refused: %v", r)
		}

		// update: ~ keeps the selector apart from +tag and -tag, which change the selected secrets
		mustOK(t, w.ku("", false, nil, "secret", "update", "app:shop", "env:dev", "~role:cf-worker", "+env:prod", "-env:dev", "--yes"))
		r = mustOK(t, w.ku("", false, nil, "secret", "list", "env:prod"))
		if strings.Count(r.out, "DB_PASSWORD") != 1 || strings.Contains(r.out, "role:cf-worker") {
			t.Fatalf("update with an exclusion: %q", r.out)
		}
		r = mustOK(t, w.ku("", false, nil, "secret", "list", "role:cf-worker"))
		if !strings.Contains(r.out, "env:dev") {
			t.Fatalf("the worker's secret must be untouched: %q", r.out)
		}

		// a confirmation is bound to the exclusion too: authorizing app:shop does not authorize app:shop ~role:cf-worker
		mustOK(t, w.ku("y\n", true, nil, "secret", "update", "app:shop", "role:cf-worker", "--authorize", "on", "--yes"))
		before := w.stepUps
		r = mustOK(t, w.ku("", false, nil, append([]string{"run", "app:shop", "env:dev"}, show...)...))
		if w.stepUps != before+1 || strings.TrimSpace(r.out) != "worker-pw" {
			t.Fatalf("authorize: steps=%d out=%q", w.stepUps, r.out)
		}
		r = mustOK(t, w.ku("", false, nil, append([]string{"run", "app:shop", "env:prod"}, show...)...))
		if w.stepUps != before+1 || strings.TrimSpace(r.out) != "api-pw" {
			t.Fatalf("an excluded run of a plain secret needs no confirmation: steps=%d out=%q", w.stepUps, r.out)
		}
	})
}

// A suggestion must leave exactly one secret: with three or more one tag may not be enough, so it can be several.
func TestPickers(t *testing.T) {
	for _, c := range []struct {
		name  string
		items []string
		want  []string
	}{
		{"only one has a tag", []string{"A app:x", "A app:x role:w"}, []string{"~role:w", "role:w"}},
		{"each has its own", []string{"A app:x env:dev", "A app:x env:prod"}, []string{"env:dev", "env:prod"}},
		{"the middle one needs two", []string{"A x:1", "A x:1 y:1", "A x:1 y:1 z:1"}, []string{"~y:1", "y:1 ~z:1", "z:1"}},
		// D has every tag the others have and none of its own: it takes all three to tell it apart
		{"all tags of one", []string{"A p:1 q:1", "A p:1 r:1", "A q:1 r:1", "A p:1 q:1 r:1"}, []string{"~r:1", "~q:1", "~p:1", "p:1 q:1 r:1"}},
		// the plain one is told apart from each role by leaving each out
		{"the one without roles", []string{"A e:d", "A e:d r:api", "A e:d r:worker"}, []string{"~r:api ~r:worker", "r:api", "r:worker"}},
	} {
		got := pickers(c.items)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Fatalf("%s: got %q want %q", c.name, got, c.want)
		}
	}
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
