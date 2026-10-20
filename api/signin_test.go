package api_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

// Opening the link printed by `ku login` shows the sign-in card; only the button goes to Google. A page that
// merely loads must not start a login (no state is created, nothing redirects).
func TestSignInCardComesBeforeGoogle(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		q := url.Values{"cli_port": {"53682"}, "cli_challenge": {strings.Repeat("c", 43)}, "cli_state": {"s"}, "cli_profile": {"some_name"}}

		card := e.do("GET", "/auth/login?"+q.Encode(), "", nil)
		body := card.Body.String()
		if card.Code != 200 || card.Header().Get("Location") != "" {
			t.Fatalf("the link must show a page, not redirect: %d", card.Code)
		}
		if !strings.Contains(body, "Continue with Google") || !strings.Contains(body, "<small>some_name</small>") || !strings.Contains(body, "go=1") {
			t.Fatalf("card: button, profile name, and a go=1 link: %s", body)
		}
		if !strings.Contains(card.Header().Get("Content-Security-Policy"), "default-src 'none'") {
			t.Fatal("same CSP as the other pages")
		}

		// the button's target redirects to Google, with the CLI parameters intact
		go1 := e.do("GET", "/auth/login?"+q.Encode()+"&go=1", "", nil)
		if go1.Code != 302 || !strings.HasPrefix(go1.Header().Get("Location"), "https://idp.test/") {
			t.Fatalf("go=1 starts the login: %d %s", go1.Code, go1.Header().Get("Location"))
		}

		// invalid or missing CLI parameters: no useless button, a failure page
		for _, bad := range []string{"", "cli_port=80&cli_challenge=x&cli_state=s", "cli_port=53682&cli_challenge=" + strings.Repeat("c", 43)} {
			r := e.do("GET", "/auth/login?"+bad, "", nil)
			if r.Code != 401 || strings.Contains(r.Body.String(), "Continue with Google") {
				t.Fatalf("%q: %d", bad, r.Code)
			}
			if r := e.do("GET", "/auth/login?go=1&"+bad, "", nil); r.Code != 401 {
				t.Fatalf("go=1 with bad parameters: %d", r.Code)
			}
		}

		// the invite page already is the button page, so its link goes straight to Google
		inv, _ := e.ids.BootstrapAdmin(t.Context(), "root@example.test")
		page := e.do("GET", "/invite?token="+inv.Token, "", nil)
		if !strings.Contains(page.Body.String(), "/auth/login?go=1&amp;invite=") {
			t.Fatalf("invite link: %s", page.Body)
		}
		u, _ := url.Parse("/auth/login?go=1&invite=" + url.QueryEscape(inv.Token))
		if r := e.do("GET", u.String(), "", nil); r.Code != 302 {
			t.Fatalf("invite login: %d", r.Code)
		}
	})
}
