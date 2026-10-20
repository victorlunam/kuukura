package main

import (
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

// `ku link <app>` creates a new app and gives the caller write access; an existing app still needs a grant.
func TestLinkCreatesANewApp(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		w, admin := userWorld(t, p)
		work := t.TempDir()
		env := map[string]string{"CWD": work}

		r := mustOK(t, w.ku("", false, env, "link", "demo"))
		if !strings.Contains(r.errOut, "✓ Created app demo and linked this folder; you can write its secrets") || strings.Contains(r.errOut, "ask an admin") {
			t.Fatalf("create:\n%q", r.errOut)
		}
		r = mustOK(t, w.ku(fakeValue+"\n", false, env, "secret", "set", "NAME", "--yes"))
		if !strings.Contains(r.errOut, "✓ Saved NAME (version 1)") {
			t.Fatalf("set:\n%q", r.errOut)
		}
		noValue(t, r, fakeValue)

		// linking again is harmless: the app exists and the creator sees its secrets, so no hint
		r = mustOK(t, w.ku("", true, env, "link", "demo"))
		if !strings.Contains(r.errOut, "✓ Linked this folder to demo") || strings.Contains(r.errOut, "ask an admin") || strings.Contains(r.errOut, "Created") {
			t.Fatalf("again:\n%q", r.errOut)
		}

		// a second person finds the app taken: linked, told whom to ask, and cannot write
		other := w.member(admin, "other@example.test")
		w.loginAs(other)
		r = mustOK(t, w.ku("", false, env, "link", "demo"))
		if !strings.Contains(r.errOut, "✓ Linked this folder to demo") || !strings.Contains(r.errOut, "ask an admin: ku workspace grant <you> write app:demo") || strings.Contains(r.errOut, "Created") {
			t.Fatalf("exists:\n%q", r.errOut)
		}
		if r := w.ku(fakeValue+"\n", false, env, "secret", "set", "NAME", "--yes"); r.code == 0 {
			t.Fatalf("no grant, no write:\n%q", r.errOut)
		}

		// a machine token never creates: the link is local only
		_, m := w.api(admin, "POST", "/workspace/invites", map[string]any{"name": "ci", "machine": true})
		key, _ := m["token"].(string)
		r = mustOK(t, w.ku("", false, map[string]string{"CWD": work, "KU_URL": w.srv.URL, "KU_TOKEN": key}, "link", "ci-app"))
		if !strings.Contains(r.errOut, "✓ Linked this folder to ci-app") {
			t.Fatalf("machine:\n%q", r.errOut)
		}
		if code, _ := w.api(admin, "POST", "/apps", map[string]string{"name": "ci-app"}); code != 201 {
			t.Fatalf("the machine must not have created ci-app: %d", code)
		}
	})
}

// An unreachable server keeps the link and fails the command.
func TestLinkKeepsTheLinkWhenTheServerFails(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		w, _ := userWorld(t, p)
		work := t.TempDir()
		env := map[string]string{"CWD": work}
		w.srv.Close()
		r := w.ku("", false, env, "link", "offline")
		if r.code != 1 || !strings.Contains(r.errOut, "✓ Linked this folder to offline") || !strings.Contains(r.errOut, "✗ The app could not be created on the server") {
			t.Fatalf("offline:\n%d %q", r.code, r.errOut)
		}
		if r := mustOK(t, w.ku("", false, env, "link")); !strings.Contains(r.out, "linked to offline") {
			t.Fatalf("link kept:\n%q", r.out)
		}
	})
}
