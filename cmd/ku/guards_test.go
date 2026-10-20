package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

func TestConfirmationGates(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p)
		mustOK(t, w.ku(fakeValue+"\n", false, nil, "secret", "set", "STRIPE_KEY", "app:shop", "env:prod", "--yes"))
		steps := func(want int, what string) {
			t.Helper()
			if w.stepUps != want {
				t.Fatalf("%s: confirmations = %d, want %d", what, w.stepUps, want)
			}
		}
		mustOK(t, w.ku("", false, nil, "secret", "list"))
		steps(0, "list")
		mustOK(t, w.ku("", false, nil, "secret", "update", "STRIPE_KEY", "--authorize", "on"))
		steps(0, "--authorize on needs no confirmation")
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
		if r.code != 1 || fileExists(marker) || !strings.Contains(r.errOut, "✗ No matching secret.") || strings.Contains(r.errOut, "app:shop") && strings.Contains(r.errOut, "STRIPE_KEY  ") {
			t.Fatalf("not permitted:\n%q", r.errOut)
		}
		noValue(t, r, fakeValue)

		// a stale session says to log in again
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

// brokenStore is a session store that cannot be read (a locked keychain, a file other users can read).
type brokenStore struct{}

func (brokenStore) Get(string) (string, error) { return "", errors.New("the keychain is locked") }
func (brokenStore) Set(string, string) error   { return nil }
func (brokenStore) Delete(string) error        { return nil }

// Only "there is no session" means "not logged in"; any other failure says what it is.
func TestUnreadableSessionIsNotReportedAsLoggedOut(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w := newWorld(t, p)
		w.admin()
		mustOK(t, w.ku("", false, nil, "profile", "add", "default", "--url", w.srv.URL))

		w.altStore = &brokenStore{}
		r := w.ku("", false, nil, "secret", "list")
		if r.code != 1 || !strings.Contains(r.errOut, "the keychain is locked") || strings.Contains(r.errOut, "not logged in") {
			t.Fatalf("unreadable session: %q", r.errOut)
		}

		w.altStore = &memStore{m: map[string]string{}}
		if r := w.ku("", false, nil, "secret", "list"); r.code != 1 || !strings.Contains(r.errOut, "not logged in. Run: ku login") {
			t.Fatalf("no session: %q", r.errOut)
		}

		// KU_URL without KU_TOKEN: there is no login to run, a token to set instead
		env := map[string]string{"KU_URL": w.srv.URL}
		if r := w.ku("", false, env, "secret", "list"); r.code != 1 || !strings.Contains(r.errOut, "Set KU_TOKEN") || strings.Contains(r.errOut, "ku login") {
			t.Fatalf("KU_URL alone: %q", r.errOut)
		}
		if r := w.ku("", false, env, "login"); r.code != 1 || !strings.Contains(r.errOut, "KU_URL or KU_TOKEN is set") {
			t.Fatalf("login with only KU_URL: %q", r.errOut)
		}
	})
}

func TestMaskingEverywhere(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p)
		cmds := []struct {
			args   []string
			code   int
			reason string // in stderr when the command is expected to fail
		}{
			{[]string{"secret", "set", "STRIPE_KEY", "app:shop", "--yes"}, 0, ""},
			{[]string{"secret", "list"}, 0, ""},
			{[]string{"secret", "update", "STRIPE_KEY", "+env:prod"}, 0, ""},
			{[]string{"secret", "revoke", "STRIPE_KEY"}, 0, ""},
			{[]string{"run", "app:shop", "--", "true"}, 1, "STRIPE_KEY is blocked"},
			{[]string{"secret", "get", "NOPE", "--reveal"}, 1, "No matching secret."},
		}
		for _, c := range cmds {
			r := w.ku(fakeValue+"\n", false, nil, c.args...)
			if r.code != c.code || !strings.Contains(r.errOut, c.reason) {
				t.Errorf("%v: exit %d (want %d), stderr %q (want %q)", c.args, r.code, c.code, r.errOut, c.reason)
			}
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

func TestWorkspaceCommands(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w := newWorld(t, p)
		admin := w.admin()
		w.loginAs(admin)
		r := mustOK(t, w.ku("", false, nil, "workspace", "invite", "new@example.test"))
		if !strings.Contains(r.out, w.srv.URL+"/invite?token=ku_") || !strings.Contains(r.errOut, "✓ Invited new@example.test") {
			t.Fatalf("invite: %q", r.out)
		}
		if !strings.Contains(r.out, "&profile=default") {
			t.Fatalf("the invite link suggests the inviter's profile name: %q", r.out)
		}
		w.member(admin, "dev@example.test")
		long := "a-very-long-person-name.with.dots@a-long-subdomain.example.test" // longer than any fixed column
		w.member(admin, long)
		mustOK(t, w.ku("", false, nil, "workspace", "group", "pay", "+dev@example.test"))
		mustOK(t, w.ku("", false, nil, "workspace", "grant", "pay", "write", "team:pay"))
		mustOK(t, w.ku("", false, nil, "workspace", "ungrant", "pay", "team:pay"))
		mustOK(t, w.ku("", false, nil, "workspace", "group", "pay", "-dev@example.test"))
		r = mustOK(t, w.ku("", false, nil, "workspace", "audit"))
		if !strings.Contains(r.out, "WHEN (UTC)") || !strings.Contains(r.out, "group_add") || !strings.Contains(r.out, "grant") {
			t.Fatalf("audit: %q", r.out)
		}
		// columns follow the content: a long email must be followed by at least two spaces, never glued to the action
		sawLong := false
		for l := range strings.SplitSeq(strings.TrimSpace(r.out), "\n") {
			if i := strings.Index(l, long); i >= 0 {
				sawLong = true
				if !strings.HasPrefix(l[i+len(long):], "  ") {
					t.Fatalf("columns run together: %q", l)
				}
			}
		}
		if !sawLong {
			t.Fatalf("the long-named person has audit rows: %q", r.out)
		}
		if r := w.ku("", false, nil, "workspace", "disable", "root@example.test"); r.code != 1 || !strings.Contains(r.errOut, "last admin") {
			t.Fatalf("last admin: %q", r.errOut)
		}
		if r := w.ku("", false, nil, "workspace", "enable", "dev@example.test"); r.code != 1 || !strings.Contains(r.errOut, "not disabled") {
			t.Fatalf("enable an active person: %q", r.errOut)
		}
		r = mustOK(t, w.ku("", false, nil, "workspace", "disable", "dev@example.test"))
		if !strings.Contains(r.errOut, "✓ Disabled dev@example.test") {
			t.Fatalf("disable: %q", r.errOut)
		}
		r = mustOK(t, w.ku("", false, nil, "workspace", "enable", "dev@example.test"))
		if !strings.Contains(r.errOut, "✓ Enabled dev@example.test") {
			t.Fatalf("enable: %q", r.errOut)
		}
		mustOK(t, w.ku("", false, nil, "workspace", "disable", "dev@example.test"))
		// a member cannot use admin commands
		dev2 := w.member(admin, "dev2@example.test")
		_ = w.store.Set("default", dev2)
		if r := w.ku("", false, nil, "workspace", "audit"); r.code != 1 || !strings.Contains(r.errOut, "don't have access") {
			t.Fatalf("member audit: %q", r.errOut)
		}
	})
}

// The agent skill tells agents to rely on `ku secret list`: it must never carry a value or a value column.
func TestListNeverShowsValues(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p)
		secretsToSet := map[string]string{"A_TEXT": fakeValue, "B_TEXT": "password=FAKE-hunter2", "C_BLOCKED": "FAKE-blocked-value"}
		for n, v := range secretsToSet {
			mustOK(t, w.ku(v+"\n", false, nil, "secret", "set", n, "app:shop", "--yes"))
		}
		cert := filepath.Join(t.TempDir(), "k.pem")
		_ = os.WriteFile(cert, []byte("-----BEGIN FAKE-----"), 0o600)
		mustOK(t, w.ku("", false, nil, "secret", "set", "D_FILE", "app:shop", "--file", cert, "--yes"))
		mustOK(t, w.ku("", false, nil, "secret", "revoke", "C_BLOCKED"))
		r := mustOK(t, w.ku("", false, nil, "secret", "list"))
		for _, v := range secretsToSet {
			noValue(t, r, v)
		}
		noValue(t, r, "BEGIN FAKE", "LS0tLS1CRUdJTiBGQUtF") // file content, plain and base64
		if first := strings.Fields(strings.SplitN(r.out, "\n", 2)[0]); strings.Join(first, " ") != "NAME VERSION TAGS" {
			t.Fatalf("list has exactly the columns name, version, tags: %v", first)
		}
	})
}

func TestSkillShipsAndForbidsReveal(t *testing.T) {
	b, err := os.ReadFile("../../SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, must := range []string{"ku run", "ku secret list", "Never run `ku secret get --reveal`", "Never print"} {
		if !strings.Contains(s, must) {
			t.Fatalf("SKILL.md must say %q", must)
		}
	}
	if strings.Count(s, "\n") > 40 {
		t.Fatal("SKILL.md must stay short")
	}
}
