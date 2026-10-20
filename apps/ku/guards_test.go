package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
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
		if r.code != 1 || !strings.Contains(r.errOut, "✗ Your session ended.\n  Run: ku login\n") {
			t.Fatalf("expired: %q", r.errOut)
		}
		_ = w.store.Delete("default")
		r = w.ku("", false, nil, "secret", "list")
		if r.code != 1 || !strings.Contains(r.errOut, "You are not logged in") {
			t.Fatalf("logged out: %q", r.errOut)
		}
		// values are never accepted as arguments: an extra word is a bad tag, not a value
		_ = w.store.Set("default", dev)
		r = w.ku("", false, nil, "secret", "set", "X", fakeValue, "--yes")
		if r.code != 2 || strings.Contains(r.out+r.errOut, "Saved") {
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
		if r := w.ku("", false, nil, "secret", "list"); r.code != 1 || !strings.Contains(r.errOut, "✗ You are not logged in.\n  Run: ku login\n") {
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
