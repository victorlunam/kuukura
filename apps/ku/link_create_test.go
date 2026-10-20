package main

import (
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

// `ku link <app> --create` makes a new app and gives the caller write access; an existing app still needs a grant.
func TestLinkCreatesANewApp(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		w, admin := userWorld(t, p)
		work := t.TempDir()
		env := map[string]string{"CWD": work}

		// no flag and no terminal: only the local link, the server is not asked
		mustOK(t, w.ku("", false, env, "link", "plain"))
		if code, _ := w.api(admin, "POST", "/apps", map[string]string{"name": "plain"}); code != 201 {
			t.Fatalf("plain must still be new: %d", code)
		}

		r := mustOK(t, w.ku("", false, env, "link", "demo", "--create"))
		if !strings.Contains(r.errOut, "✓ Linked this folder to demo") || !strings.Contains(r.errOut, "✓ Created app demo; you can write its secrets") {
			t.Fatalf("create:\n%q", r.errOut)
		}
		r = mustOK(t, w.ku(fakeValue+"\n", false, env, "secret", "set", "NAME", "--yes"))
		if !strings.Contains(r.errOut, "✓ Saved NAME (version 1)") {
			t.Fatalf("set:\n%q", r.errOut)
		}
		noValue(t, r, fakeValue)

		// a second person finds the app taken: linked, told whom to ask, and cannot write
		other := w.member(admin, "other@example.test")
		w.loginAs(other)
		r = mustOK(t, w.ku("", false, env, "link", "demo", "--create"))
		if !strings.Contains(r.errOut, "demo already exists. To get access, ask an admin: ku workspace grant <you> write app:demo") || strings.Contains(r.errOut, "Created") {
			t.Fatalf("exists:\n%q", r.errOut)
		}
		if r := w.ku(fakeValue+"\n", false, env, "secret", "set", "NAME", "--yes"); r.code == 0 {
			t.Fatalf("no grant, no write:\n%q", r.errOut)
		}

		// on a terminal the person is asked; no creates nothing
		r = mustOK(t, w.ku("n\n", true, env, "link", "asked"))
		if !strings.Contains(r.errOut, "Create app asked and give you write access if it is new? (y/N)") || strings.Contains(r.errOut, "Created") {
			t.Fatalf("declined:\n%q", r.errOut)
		}
		r = mustOK(t, w.ku("y\n", true, env, "link", "asked"))
		if !strings.Contains(r.errOut, "✓ Created app asked") {
			t.Fatalf("accepted:\n%q", r.errOut)
		}

		// a machine token never creates
		_, m := w.api(admin, "POST", "/workspace/invites", map[string]any{"name": "ci", "machine": true})
		key, _ := m["token"].(string)
		r = w.ku("", false, map[string]string{"CWD": work, "KU_URL": w.srv.URL, "KU_TOKEN": key}, "link", "ci-app", "--create")
		if r.code == 0 || !strings.Contains(r.errOut, "A machine token cannot create apps") {
			t.Fatalf("machine:\n%q", r.errOut)
		}
	})
}
