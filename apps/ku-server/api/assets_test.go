package api_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

func TestBrandAssetsAndPageHygiene(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		for _, path := range []string{"/favicon.svg", "/assets/logo.svg", "/assets/mark.svg", "/assets/banner.svg"} {
			r := e.do("GET", path, "", nil)
			if r.Code != 200 || r.Header().Get("Content-Type") != "image/svg+xml" || !strings.HasPrefix(strings.TrimSpace(r.Body.String()), "<svg") {
				t.Fatalf("%s: %d %s", path, r.Code, r.Header().Get("Content-Type"))
			}
			if !strings.Contains(r.Header().Get("Content-Security-Policy"), "sandbox") || !strings.Contains(r.Header().Get("Cache-Control"), "max-age") {
				t.Fatalf("%s: assets are sandboxed and cacheable", path)
			}
		}
		if r := e.do("GET", "/assets/../go.mod", "", nil); r.Code == 200 {
			t.Fatal("only the listed assets are served")
		}
		if r := e.do("GET", "/assets/nope.svg", "", nil); r.Code != 404 {
			t.Fatalf("unknown asset: %d", r.Code)
		}

		inv, _ := e.ids.BootstrapAdmin(t.Context(), "root@example.test")
		r := e.do("GET", "/invite?token="+inv.Token, "", nil)
		body := r.Body.String()
		if r.Code != 200 || !strings.Contains(body, `href="/favicon.svg"`) || !strings.Contains(body, "root@example.test") || !strings.Contains(body, "Continue with Google") {
			t.Fatalf("invite page: %d", r.Code)
		}
		// no external resources: every URL in the page is same-origin
		for _, m := range regexp.MustCompile(`(?:src|href)="([^"#]+)"`).FindAllStringSubmatch(body, -1) {
			if !strings.HasPrefix(m[1], "/") {
				t.Fatalf("external resource in page: %s", m[1])
			}
		}
		if strings.Contains(body, "style=") {
			t.Fatal("inline style attributes would be blocked by the CSP")
		}
		csp := r.Header().Get("Content-Security-Policy")
		for _, must := range []string{"default-src 'none'", "img-src 'self'", "frame-ancestors 'none'"} {
			if !strings.Contains(csp, must) {
				t.Fatalf("CSP lacks %q: %s", must, csp)
			}
		}
		// an invalid invite renders a friendly page, not a bare error
		r = e.do("GET", "/invite?token=ku_nope", "", nil)
		if r.Code != 404 || !strings.Contains(r.Body.String(), "This invite is not valid") {
			t.Fatalf("bad invite page: %d", r.Code)
		}
	})
}
