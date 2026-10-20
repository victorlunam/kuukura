package api

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/internal/auth"
)

// TestRenderPreview writes every page to $KU_PREVIEW_DIR for a visual check. Without the variable it only
// proves that every page renders.
func TestRenderPreview(t *testing.T) {
	dir := os.Getenv("KU_PREVIEW_DIR")
	s := &Server{Deps: Deps{BaseURL: "https://vault.example.com"}}
	e := echo.New()
	pages := map[string]func(c echo.Context) error{
		"invite": func(c echo.Context) error {
			return s.page(c, 200, pageData{Title: "You're invited", Mode: "invite", Art: art("vault-empty"), Step: 1, Email: "dev@example.com", Link: "/auth/login?invite=ku_x"})
		},
		"mfa":    func(c echo.Context) error { return s.factorPage(c, auth.Pending{Token: "ku_x", Mode: "mfa"}) },
		"enroll": func(c echo.Context) error { return s.factorPage(c, auth.Pending{Token: "ku_x", Mode: "enroll"}) },
		"stepup": func(c echo.Context) error {
			return s.page(c, 200, pageData{Title: "Confirm it's you", Mode: "stepup", ID: "abc", Art: art("confirm"), ArtDone: art("done"), HasPasskey: true, HasTOTP: true})
		},
		"stepup-totp": func(c echo.Context) error {
			return s.page(c, 200, pageData{Title: "Confirm it's you", Mode: "stepup", ID: "abc", Art: art("confirm"), ArtDone: art("done"), HasTOTP: true})
		},
		"done": s.donePage,
		"fail": s.failPage,
	}
	for name, fn := range pages {
		rec := httptest.NewRecorder()
		c := e.NewContext(httptest.NewRequest("GET", "/?id=abc", nil), rec)
		if err := fn(c); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rec.Code != 200 && rec.Code != 401 || rec.Body.Len() < 2000 {
			t.Fatalf("%s: status %d, %d bytes", name, rec.Code, rec.Body.Len())
		}
		if dir != "" {
			if err := os.WriteFile(filepath.Join(dir, name+".html"), rec.Body.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	svg, err := qrSVG("otpauth://totp/kuukura:dev@example.com?secret=JBSWY3DPEHPK3PXP&issuer=kuukura")
	if err != nil || len(svg) < 200 {
		t.Fatalf("qr: %v", err)
	}
}
