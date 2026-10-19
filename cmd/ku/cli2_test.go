package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

func TestTouchIDGates(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p)
		mustOK(t, w.ku(fakeValue+"\n", false, nil, "secret", "set", "STRIPE_KEY", "app:shop", "env:prod", "--yes"))
		steps := func(want int, what string) {
			t.Helper()
			if w.stepUps != want {
				t.Fatalf("%s: Touch ID confirmations = %d, want %d", what, w.stepUps, want)
			}
		}
		mustOK(t, w.ku("", false, nil, "secret", "list"))
		steps(0, "list")
		mustOK(t, w.ku("", false, nil, "secret", "update", "STRIPE_KEY", "--authorize", "on"))
		steps(0, "--authorize on needs no Touch ID")
		mustOK(t, w.ku("", false, nil, "secret", "get", "STRIPE_KEY", "--reveal"))
		steps(1, "reveal")
		mustOK(t, w.ku("", false, nil, "secret", "get", "STRIPE_KEY", "--out", filepath.Join(t.TempDir(), "o")))
		steps(2, "--out")
		mustOK(t, w.ku("", false, nil, "run", "app:shop", "--", "true"))
		steps(3, "requires_authorize in run")
		mustOK(t, w.ku("", false, nil, "secret", "update", "STRIPE_KEY", "--authorize", "off"))
		steps(4, "--authorize off")
		mustOK(t, w.ku("", false, nil, "run", "app:shop", "--", "true"))
		steps(4, "run after authorize off")
	})
}

func TestFailClosedAndMasking(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w := newWorld(t, p)
		admin := w.admin()
		dev := w.member(admin, "dev@example.test")
		w.grant(admin, "dev@example.test", "write", "app:shop")
		w.loginAs(dev)
		mustOK(t, w.ku(fakeValue+"\n", false, nil, "secret", "set", "STRIPE_KEY", "app:shop", "env:prod", "--yes"))

		// a second person with no grants: nothing is injected and the command does not start
		other := w.member(admin, "other@example.test")
		_ = w.store.Set("default", other)
		marker := filepath.Join(t.TempDir(), "ran")
		r := w.ku("", false, nil, "run", "STRIPE_KEY", "app:shop", "--", "touch", marker)
		if r.code != 1 || fileExists(marker) || !strings.Contains(r.errOut, "✗ You don't have access to") {
			t.Fatalf("not permitted:\n%q", r.errOut)
		}
		noValue(t, r, fakeValue)

		// errors and logs never carry the value; a stale session says to log in
		_ = w.store.Set("default", "ku_expired")
		r = w.ku("", false, nil, "secret", "list")
		if r.code != 1 || !strings.Contains(r.errOut, "Your session ended. Run: ku login") {
			t.Fatalf("expired: %q", r.errOut)
		}
		_ = w.store.Delete("default")
		r = w.ku("", false, nil, "secret", "list")
		if r.code != 1 || !strings.Contains(r.errOut, "not logged in") {
			t.Fatalf("logged out: %q", r.errOut)
		}
		// values are never accepted as arguments: an extra word is a bad tag, not a value
		_ = w.store.Set("default", dev)
		r = w.ku("", false, nil, "secret", "set", "X", fakeValue, "--yes")
		if r.code != 1 || strings.Contains(r.out+r.errOut, "Saved") {
			t.Fatalf("argument values must be rejected: %v", r)
		}
	})
}

func TestMaskingEverywhere(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p)
		cmds := [][]string{
			{"secret", "set", "STRIPE_KEY", "app:shop", "--yes"},
			{"secret", "list"},
			{"secret", "update", "STRIPE_KEY", "+env:prod"},
			{"secret", "revoke", "STRIPE_KEY"},
			{"run", "app:shop", "--", "true"},
			{"secret", "get", "NOPE", "--reveal"},
		}
		for _, c := range cmds {
			r := w.ku(fakeValue+"\n", false, nil, c...)
			noValue(t, r, fakeValue)
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
		token := ""
		for _, l := range strings.Split(r.out, "\n") {
			if strings.HasPrefix(l, "ku_") {
				token = l
			}
		}
		if token == "" || !strings.Contains(r.out, "KU_TOKEN") {
			t.Fatalf("machine invite: %q", r.out)
		}
		mustOK(t, w.ku("", false, nil, "workspace", "grant", "ci-deploy", "read", "app:shop"))

		// ephemeral profile: no config file, no Keychain
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
		if r := w.ku("", false, env, "secret", "get", "DEPLOY_KEY", "--reveal"); r.code != 1 {
			t.Fatalf("machine reveal: %v", r)
		}
		if w.stepUps != 0 {
			t.Fatal("machines never get a Touch ID step-up")
		}
	})
}

func TestWorkspaceCommands(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w := newWorld(t, p)
		admin := w.admin()
		w.loginAs(admin)
		r := mustOK(t, w.ku("", false, nil, "workspace", "invite", "new@example.test"))
		if !strings.Contains(r.out, "https://"+testDomain+"/invite?token=ku_") {
			t.Fatalf("invite: %q", r.out)
		}
		w.member(admin, "dev@example.test")
		mustOK(t, w.ku("", false, nil, "workspace", "group", "pay", "+dev@example.test"))
		mustOK(t, w.ku("", false, nil, "workspace", "grant", "pay", "write", "team:pay"))
		mustOK(t, w.ku("", false, nil, "workspace", "ungrant", "pay", "team:pay"))
		mustOK(t, w.ku("", false, nil, "workspace", "group", "pay", "-dev@example.test"))
		r = mustOK(t, w.ku("", false, nil, "workspace", "audit"))
		if !strings.Contains(r.out, "WHEN (UTC)") || !strings.Contains(r.out, "group_add") || !strings.Contains(r.out, "grant") {
			t.Fatalf("audit: %q", r.out)
		}
		if r := w.ku("", false, nil, "workspace", "remove", "root@example.test"); r.code != 1 || !strings.Contains(r.errOut, "last admin") {
			t.Fatalf("last admin: %q", r.errOut)
		}
		mustOK(t, w.ku("", false, nil, "workspace", "remove", "dev@example.test"))
		// a member cannot use admin commands
		dev2 := w.member(admin, "dev2@example.test")
		_ = w.store.Set("default", dev2)
		if r := w.ku("", false, nil, "workspace", "audit"); r.code != 1 || !strings.Contains(r.errOut, "don't have access") {
			t.Fatalf("member audit: %q", r.errOut)
		}
	})
}
