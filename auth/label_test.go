package auth_test

import (
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/auth"
	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

// callbackFor plays the provider redirect for the URL StartLogin returned.
func (e *env) callbackFor(authURL string, id auth.Identity) (auth.Pending, error) {
	u, _ := url.Parse(authURL)
	code := uuid.NewString()
	e.idp.byCode[code] = id
	return e.svc.Callback(ctx, u.Query().Get("state"), code, "203.0.113.9")
}

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

// stateOf extracts the state parameter from the provider URL StartLogin returned.
func stateOf(authURL string) string {
	u, _ := url.Parse(authURL)
	return u.Query().Get("state")
}
