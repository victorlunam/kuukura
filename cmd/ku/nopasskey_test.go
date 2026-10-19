package main

import (
	"strings"
	"testing"
	"time"

	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

// An account that only has an authenticator app can sign in, but a Touch ID confirmation needs a passkey. The CLI
// must say so right away instead of opening a page that cannot succeed and waiting two minutes.
func TestRevealWithoutPasskeyFailsFast(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p)
		mustOK(t, w.ku("v\n", false, nil, "secret", "set", "DEMO_KEY", "app:shop", "--yes"))
		if _, err := p.DB().Exec(`DELETE FROM credentials WHERE kind = 'passkey'`); err != nil {
			t.Fatal(err)
		}

		start := time.Now()
		r := w.ku("", false, nil, "secret", "get", "DEMO_KEY", "--reveal")
		if r.code != 1 || !strings.Contains(r.errOut, "Touch ID needs a passkey") || !strings.Contains(r.errOut, "authenticator app") {
			t.Fatalf("expected a clear passkey message: %q", r.errOut)
		}
		if w.stepUps != 0 || time.Since(start) > 5*time.Second || strings.Contains(r.errOut, "copy this link") {
			t.Fatal("it must fail before opening any confirmation page")
		}
		// plain commands keep working without a passkey
		mustOK(t, w.ku("", false, nil, "secret", "list"))
		mustOK(t, w.ku("", false, nil, "run", "app:shop", "--", "true"))
	})
}
