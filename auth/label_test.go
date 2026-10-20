package auth_test

import (
	"testing"

	"github.com/victorlunam/kuukura/auth"
	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

// The CLI's profile name travels through the Google redirect so the pages can show it.
func TestProfileNameSurvivesLogin(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		g := auth.Identity{Subject: "sub-l", Email: "l@example.test", EmailVerified: true}

		for profile, want := range map[string]string{"scratch": "scratch", "Bad Name!": "", "": ""} {
			inv := e.bootstrap("l@example.test") // a fresh invite per attempt: each callback consumes one
			c := newCLI()
			c.params.Profile = profile
			u, err := e.svc.StartLogin(inv, c.params)
			if err != nil {
				t.Fatal(err)
			}
			pd, err := e.callbackFor(u, g)
			if err != nil {
				t.Fatal(err)
			}
			if pd.Profile != want {
				t.Fatalf("profile %q: got %q want %q", profile, pd.Profile, want)
			}
		}
	})
}
