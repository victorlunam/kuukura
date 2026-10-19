package auth

import (
	"net/url"
	"testing"

	"golang.org/x/oauth2"
)

// The Google URL must ask for the account chooser and carry PKCE, state and nonce.
func TestGoogleAuthURL(t *testing.T) {
	g := &Google{cfg: oauth2.Config{ClientID: "fake.apps.googleusercontent.com", RedirectURL: "https://vault.example.com/auth/callback",
		Endpoint: oauth2.Endpoint{AuthURL: "https://accounts.example.test/auth"}, Scopes: []string{"openid", "email"}}}
	u, err := url.Parse(g.AuthURL("st4te", "n0nce", oauth2.GenerateVerifier()))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("prompt") != "select_account" {
		t.Fatalf("prompt = %q: the account chooser must always be shown", q.Get("prompt"))
	}
	if q.Get("state") != "st4te" || q.Get("nonce") != "n0nce" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("response_type") != "code" {
		t.Fatalf("missing state, nonce or PKCE: %v", q)
	}
}
