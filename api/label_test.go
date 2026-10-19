package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/auth"
)

// Two denials are about the account the person just chose, so the page says so (and names that account, escaped);
// every other reason keeps the generic message and never echoes an email.
func TestLoginFailedPages(t *testing.T) {
	render := func(reason, email string) string {
		s := &Server{Deps: Deps{BaseURL: "https://vault.example.com"}}
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(httptest.NewRequest("GET", "/auth/callback", nil), rec)
		if err := s.loginFailedPage(c, reason, email); err != nil {
			t.Fatal(err)
		}
		if rec.Code != 401 {
			t.Fatalf("status %d", rec.Code)
		}
		return rec.Body.String()
	}
	b := render("no_identity_for_this_google_account", "stranger@example.test")
	if !strings.Contains(b, "This Google account has no access") || !strings.Contains(b, "You signed in with <b>stranger@example.test</b>") {
		t.Fatal("the not-invited account is named")
	}
	b = render("invite_email_mismatch", "other@example.test")
	if !strings.Contains(b, "Wrong Google account for this invite") || !strings.Contains(b, "still valid") {
		t.Fatal("wrong account for an invite")
	}
	for _, reason := range []string{"unknown_state", "invite_invalid", "disabled", "provider_exchange_failed", "internal", ""} {
		b := render(reason, "leak@example.test")
		if !strings.Contains(b, "The link may have expired") || strings.Contains(b, "leak@example.test") {
			t.Fatalf("reason %q must stay generic and never echo an email", reason)
		}
	}
	if b := render("no_identity_for_this_google_account", "<script>x</script>@e.test"); strings.Contains(b, "<script>x") {
		t.Fatal("the email must be HTML-escaped")
	}
}

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
