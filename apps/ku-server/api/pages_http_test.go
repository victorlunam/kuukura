package api_test

import (
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

func TestPagesAreLockedDown(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		inv, _ := e.ids.BootstrapAdmin(t.Context(), "root@example.test")
		r := e.do("GET", "/invite?token="+inv.Token, "", nil)
		csp := r.Header().Get("Content-Security-Policy")
		if r.Code != 200 || !strings.Contains(csp, "default-src 'none'") || !strings.Contains(r.Body.String(), "/auth/login?go=1&amp;invite=") {
			t.Fatalf("invite page: %d %s", r.Code, csp)
		}
		if r := e.do("GET", "/invite?token=ku_nope", "", nil); r.Code != 404 {
			t.Fatalf("bad invite: %d", r.Code)
		}
		if strings.Contains(e.logs.String(), inv.Token) {
			t.Fatal("invite tokens are never logged")
		}
		// the home page needs no sign-in and shows the command with this server's address
		r = e.do("GET", "/", "", nil)
		if r.Code != 200 || !strings.HasPrefix(r.Header().Get("Content-Type"), "text/html") ||
			!strings.Contains(r.Header().Get("Content-Security-Policy"), "default-src 'none'") ||
			!strings.Contains(r.Body.String(), "ku profile add vault.example.test --url https://vault.example.test") {
			t.Fatalf("home page: %d %s", r.Code, r.Body)
		}
		if r := e.do("HEAD", "/", "", nil); r.Code != 200 {
			t.Fatalf("home page HEAD: %d", r.Code)
		}
		e.problem(e.do("GET", "/nope", "", nil), 401, "unauthorized") // API clients still get problem+json
		// over plain HTTP a browser gets a readable page, an API client keeps the problem
		r = e.do("GET", "/", "", nil, "X-Forwarded-Proto", "http", "Accept", "text/html,application/xhtml+xml")
		if r.Code != 400 || !strings.HasPrefix(r.Header().Get("Content-Type"), "text/html") || !strings.Contains(r.Body.String(), "only works over HTTPS") ||
			!strings.Contains(r.Header().Get("Content-Security-Policy"), "default-src 'none'") {
			t.Fatalf("https page: %d %s", r.Code, r.Body)
		}
		e.problem(e.do("GET", "/", "", nil, "X-Forwarded-Proto", "http", "Accept", "application/json"), 400, "https-required")
		e.problem(e.do("POST", "/auth/token", "", "{}", "X-Forwarded-Proto", "http", "Accept", "text/html"), 400, "https-required")
		// login needs valid CLI parameters unless it is an invite acceptance
		if r := e.do("GET", "/auth/login", "", nil); r.Code != 401 {
			t.Fatalf("login without CLI parameters: %d", r.Code)
		}
	})
}
