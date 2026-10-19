package auth_test

import (
	"errors"
	"testing"

	"github.com/victorlunam/kuukura/auth"
	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

// A failed login is one generic error for the user, but the server log gets a reason code, so an operator can tell
// "wrong Google account" from "expired link" from "Google rejected the code" without guessing.
func TestLoginDenialReasons(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		good := auth.Identity{Subject: "sub-ok", Email: "ok@example.test", EmailVerified: true}

		reason := func(err error) string {
			t.Helper()
			if !errors.Is(err, auth.ErrLogin) || err.Error() != auth.ErrLogin.Error() {
				t.Fatalf("the user-facing error must stay generic: %v", err)
			}
			r, _ := auth.LoginReason(err)
			return r
		}
		start := func(invite string) string {
			u, err := e.svc.StartLogin(invite, newCLI().params)
			if err != nil {
				t.Fatal(err)
			}
			return u
		}

		if _, err := e.svc.Callback(ctx, "no-such-state", "code", "203.0.113.9"); reason(err) != "unknown_state" {
			t.Fatalf("unknown state: %v", err)
		}
		// Google did not accept the code (the fake provider rejects codes it does not know)
		if _, err := e.svc.Callback(ctx, stateOf(start("")), "bad-code", "203.0.113.9"); reason(err) != "provider_exchange_failed" {
			t.Fatalf("exchange: %v", err)
		}
		// a Google account that was never invited
		_, err := e.callbackFor(start(""), good)
		if reason(err) != "no_identity_for_this_google_account" || auth.LoginEmail(err) != "ok@example.test" {
			t.Fatalf("not invited: %v (email %q)", err, auth.LoginEmail(err))
		}
		if _, err := e.callbackFor(start(""), auth.Identity{Subject: "s", Email: "x@example.test"}); reason(err) != "email_not_verified" {
			t.Fatalf("unverified: %v", err)
		}
		// an invite for someone else
		inv := e.bootstrap("invited@example.test")
		if _, err := e.callbackFor(start(inv), good); reason(err) != "invite_email_mismatch" {
			t.Fatalf("wrong account for the invite: %v", err)
		}
		// the same invite still works for the right account (a mismatch does not burn it)
		if _, err := e.callbackFor(start(inv), auth.Identity{Subject: "sub-i", Email: "invited@example.test", EmailVerified: true}); err != nil {
			t.Fatalf("a mismatch must not consume the invite: %v", err)
		}
		if _, err := e.callbackFor(start(inv), auth.Identity{Subject: "sub-i", Email: "invited@example.test", EmailVerified: true}); reason(err) != "invite_invalid" {
			t.Fatalf("used invite: %v", err)
		}
	})
}
