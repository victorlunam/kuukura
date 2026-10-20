package main

import (
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

// ku logout ends the session on the server (a copy of the token stops working) and forgets it on this machine;
// running it again is harmless.
func TestLogoutEndsTheSessionEverywhere(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w := newWorld(t, p)
		admin := w.admin()
		user := w.member(admin, "dev@example.test")
		w.loginAs(user)
		mustOK(t, w.ku("", false, nil, "secret", "list"))

		r := mustOK(t, w.ku("", false, nil, "logout"))
		if !strings.Contains(r.errOut, "✓ Signed out of default") {
			t.Fatalf("logout: %q", r.errOut)
		}
		if tok, _ := w.sessionStore().Get("default"); tok != "" {
			t.Fatal("the local copy must be gone")
		}
		if code, _ := w.api(user, "GET", "/secrets", nil); code != 401 {
			t.Fatalf("the session must be over on the server, got %d", code)
		}
		if r := w.ku("", false, nil, "secret", "list"); r.code == 0 || !strings.Contains(r.errOut, "ku login") {
			t.Fatalf("after logout the CLI asks to sign in: %q", r.errOut)
		}

		r = mustOK(t, w.ku("", false, nil, "logout"))
		if !strings.Contains(r.errOut, "Not signed in to default") {
			t.Fatalf("second logout: %q", r.errOut)
		}
	})
}
