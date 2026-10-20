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
		// login needs valid CLI parameters unless it is an invite acceptance
		if r := e.do("GET", "/auth/login", "", nil); r.Code != 401 {
			t.Fatalf("login without CLI parameters: %d", r.Code)
		}
	})
}
