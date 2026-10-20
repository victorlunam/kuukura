package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

// A confirmation uses the second step the account has. An account with only an authenticator app confirms
// with a code in the browser (no passkey needed), and the CLI words its prompt accordingly.
func TestAuthenticatorAppAccountConfirmsWithItsCode(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w := newWorld(t, p)
		admin := w.admin()
		code, m := w.api(admin, "POST", "/workspace/invites", map[string]any{"email": "totp@example.test"})
		if code != 201 {
			t.Fatalf("invite: %d %v", code, m)
		}
		link := m["link"].(string)
		tok := link[strings.Index(link, "token=")+len("token="):]
		tok, _, _ = strings.Cut(tok, "&")
		session := w.onboardTOTP(tok, "totp@example.test")
		w.grant(admin, "totp@example.test", "write", "app:shop")
		w.loginAs(session)

		mustOK(t, w.ku("v\n", false, nil, "secret", "set", "DEMO_KEY", "app:shop", "--yes"))

		r := mustOK(t, w.ku("", false, nil, "secret", "get", "DEMO_KEY", "--reveal"))
		if r.out != "v" || w.stepUps != 1 {
			t.Fatalf("reveal with an authenticator code: %q steps=%d err=%q", r.out, w.stepUps, r.errOut)
		}
		if !strings.Contains(r.errOut, "Confirm in your browser... ✓") || strings.Contains(r.errOut, "Touch ID") {
			t.Fatalf("the prompt must not promise Touch ID to an account that has none: %q", r.errOut)
		}

		out := filepath.Join(t.TempDir(), "k.txt")
		mustOK(t, w.ku("", false, nil, "secret", "get", "DEMO_KEY", "--out", out))
		if w.stepUps != 2 {
			t.Fatalf("--out confirms too: %d", w.stepUps)
		}

		// requires_authorize and --authorize off use the same confirmation
		mustOK(t, w.ku("", false, nil, "secret", "update", "DEMO_KEY", "--authorize", "on"))
		mustOK(t, w.ku("", false, nil, "run", "app:shop", "--", "true"))
		mustOK(t, w.ku("", false, nil, "secret", "update", "DEMO_KEY", "--authorize", "off"))
		if w.stepUps != 4 {
			t.Fatalf("run and --authorize off confirm: %d", w.stepUps)
		}

		// ordinary commands never confirm
		mustOK(t, w.ku("", false, nil, "secret", "list"))
		mustOK(t, w.ku("", false, nil, "run", "app:shop", "--", "true"))
		if w.stepUps != 4 {
			t.Fatalf("plain commands must not ask: %d", w.stepUps)
		}
	})
}
