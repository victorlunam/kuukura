package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/auth"
)

// The small label in the page header: the CLI's profile name when it sent one, else the instance name
// (VAULT_NAME), else the host. It is display-only text and must never be able to inject markup.
func TestHeaderLabel(t *testing.T) {
	render := func(name string, fn func(s *Server, c echo.Context) error, target string) string {
		s := &Server{Deps: Deps{BaseURL: "https://vault.example.com", Name: name}}
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(httptest.NewRequest("GET", target, nil), rec)
		if err := fn(s, c); err != nil {
			t.Fatal(err)
		}
		return rec.Body.String()
	}
	has := func(body, label string) bool { return strings.Contains(body, "<small>"+label+"</small>") }
	factor := func(s *Server, c echo.Context) error {
		return s.factorPage(c, auth.Pending{Token: "ku_x", Mode: "mfa", Profile: "scratch"})
	}
	noProfile := func(s *Server, c echo.Context) error {
		return s.factorPage(c, auth.Pending{Token: "ku_x", Mode: "mfa"})
	}

	if b := render("", noProfile, "/"); !has(b, "vault.example.com") {
		t.Fatal("defaults to the host")
	}
	if b := render("neodev", noProfile, "/"); !has(b, "neodev") {
		t.Fatal("uses the instance name")
	}
	if b := render("neodev", factor, "/"); !has(b, "scratch") {
		t.Fatal("the CLI profile name wins")
	}
	step := func(s *Server, c echo.Context) error { return s.stepUpPage(c) }
	if b := render("neodev", step, "/stepup?id=abc&profile=scratch"); !has(b, "scratch") {
		t.Fatal("step-up page shows the profile name")
	}
	// anything that is not a plain profile name is ignored, never echoed into the page
	for _, bad := range []string{"%3Cscript%3Ealert(1)%3C/script%3E", "a%20b", "UPPER", strings.Repeat("a", 40)} {
		b := render("neodev", step, "/stepup?id=abc&profile="+bad)
		if !has(b, "neodev") || strings.Contains(b, "<script>alert") || strings.Contains(b, "UPPER") {
			t.Fatalf("unsafe label %q must fall back to the instance name", bad)
		}
	}
}
