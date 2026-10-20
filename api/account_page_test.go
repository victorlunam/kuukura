package api_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

// The link from `ku account factor add` works once, and only the button on its card spends it: a link preview or
// prefetch that merely loads the page must not burn it.
func TestAddFactorLinkNeedsTheButton(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		admin, dev := e.admin()

		grant := e.stepUp(admin, dev, "factor_add", "totp")
		r := e.do("POST", "/account/factors", admin, map[string]string{"kind": "totp", "profile": "work"}, "X-Step-Up", grant)
		if r.Code != 201 {
			t.Fatalf("add: %d %s", r.Code, r.Body)
		}
		link := strings.TrimPrefix(r.json()["url"].(string), "https://"+domain)

		for range 3 { // any number of previews
			card := e.do("GET", link, "", nil)
			b := card.Body.String()
			if card.Code != 200 || !strings.Contains(b, `data-mode="addask"`) || strings.Contains(b, `data-mode="add"`) || !strings.Contains(b, "<small>work</small>") {
				t.Fatalf("card: %d", card.Code)
			}
			if !regexp.MustCompile(`data-t=""`).MatchString(b) {
				t.Fatal("the card holds no session")
			}
		}
		go1 := e.do("GET", link+"&go=1", "", nil)
		if b := go1.Body.String(); go1.Code != 200 || !strings.Contains(b, `data-mode="add"`) || strings.Contains(b, `data-t=""`) {
			t.Fatalf("the button opens the registration: %d", go1.Code)
		}
		if again := e.do("GET", link+"&go=1", "", nil); again.Code != 404 || !strings.Contains(again.Body.String(), "no longer valid") {
			t.Fatalf("the link works once: %d", again.Code)
		}
	})
}
