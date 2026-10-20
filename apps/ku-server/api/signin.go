package api

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/internal/auth"
)

// login starts the provider flow. cli_* are the CLI's localhost PKCE parameters.
func (s *Server) login(c echo.Context) error {
	port, _ := strconv.Atoi(c.QueryParam("cli_port"))
	cli := auth.CLIParams{Port: port, Challenge: c.QueryParam("cli_challenge"), State: c.QueryParam("cli_state")}
	if port == 0 && c.QueryParam("cli_challenge") == "" && c.QueryParam("cli_state") == "" {
		cli = auth.CLIParams{}
	}
	cli.Profile = auth.CleanLabel(c.QueryParam("cli_profile")) // display only
	invite := c.QueryParam("invite")
	if !auth.ValidCLIParams(invite, cli) {
		return s.failPage(c)
	}
	// Opening the link from the terminal shows the sign-in card first; only the button (go=1) goes to Google.
	// A page that merely loads never starts a login.
	if c.QueryParam("go") == "" {
		return s.signInPage(c, cli.Profile, "/auth/login?"+c.QueryString()+"&go=1")
	}
	u, err := s.Auth.StartLogin(invite, cli)
	if err != nil {
		return s.failPage(c)
	}
	return c.Redirect(http.StatusFound, u)
}

func (s *Server) callback(c echo.Context) error {
	if e := c.QueryParam("error"); e != "" { // Google reported a problem (access_denied, ...)
		s.Log.Warn("login denied", "id", requestID(c), "reason", "provider_returned_error", "detail", auth.CleanLabel(strings.ToLower(e)))
		return s.failPage(c)
	}
	p, err := s.Auth.Callback(c.Request().Context(), c.QueryParam("state"), c.QueryParam("code"), c.RealIP())
	if err != nil {
		reason, detail := auth.LoginReason(err)
		s.Log.Warn("login denied", "id", requestID(c), "reason", reason, "detail", detail) // codes only, no user data
		return s.loginFailedPage(c, reason, auth.LoginEmail(err))
	}
	return s.factorPage(c, p)
}

// denied answers a failed login or confirmation step with the generic 401. An ordinary failure (ErrLogin) is
// already in the audit log; anything else is a broken dependency, and the operator needs its cause.
func (s *Server) denied(c echo.Context, err error) error {
	if !errors.Is(err, auth.ErrLogin) {
		s.Log.Error("login step failed", "id", requestID(c), "route", c.Path(), "err", err)
	}
	return errUnauthorized
}

type tokenReq struct {
	Code     string `json:"code"`
	Verifier string `json:"verifier"`
}

// token trades the CLI's one-time code plus PKCE verifier for a session.
func (s *Server) token(c echo.Context) error {
	var r tokenReq
	if err := decode(c, &r); err != nil {
		return err
	}
	iss, err := s.Auth.ExchangeCode(c.Request().Context(), r.Code, r.Verifier)
	if err != nil {
		return s.denied(c, err)
	}
	return c.JSON(http.StatusOK, map[string]any{"token": iss.Raw, "expires_at": iss.ExpiresAt})
}

func (s *Server) logout(c echo.Context) error {
	if err := s.Auth.Logout(c.Request().Context(), info(c), c.RealIP()); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

func (s *Server) donePage(c echo.Context) error {
	return s.page(c, http.StatusOK, pageData{Title: "You're all set", Mode: "done", Art: art("done"), Step: 3,
		Suggest: s.suggestProfile(auth.CleanLabel(c.QueryParam("profile")))})
}

func (s *Server) failPage(c echo.Context) error {
	return s.page(c, http.StatusUnauthorized, pageData{
		Title: "That did not work", Mode: "fail", Art: art("alert"), Hint: true,
		Detail: "The link may have expired or been used already. Ask your admin for a new invite, or start again from your terminal:",
	})
}

// signInPage is the first card of `ku login`: the same look as the invite, with the sign-in button.
func (s *Server) signInPage(c echo.Context, profile, link string) error {
	return s.page(c, http.StatusOK, pageData{Title: "Sign in", Mode: "signin", Art: art("vault-empty"), Link: link, Label: profile})
}

// loginFailedPage explains the two failures that are about the account the person just chose (it is shown
// only back to them, so it reveals nothing about anyone else); every other reason stays generic.
func (s *Server) loginFailedPage(c echo.Context, reason, email string) error {
	switch reason {
	case "no_identity_for_this_account":
		return s.page(c, http.StatusUnauthorized, pageData{
			Title: "No account found", Mode: "fail", Art: art("alert"), Hint: true, Email: email,
			Detail: "This account is not registered in this vault. It is invite-only: sign in with the account you were invited with, or ask your admin to invite this one.",
		})
	case "invite_email_mismatch":
		return s.page(c, http.StatusUnauthorized, pageData{
			Title: "Wrong account for this invite", Mode: "fail", Art: art("alert"), Email: email,
			Detail: "This invite belongs to a different account. Open the invite link again and choose the account it was sent to. The invite is still valid.",
		})
	}
	return s.failPage(c)
}

var slugRE = regexp.MustCompile(`[^a-z0-9._-]+`)

// suggestProfile picks the name shown in `ku profile add <name> --url ...`. It is only a suggestion: the
// name is a local label and the URL is what matters. Order: the inviter's profile name, the instance name,
// the host.
func (s *Server) suggestProfile(fromInviter string) string {
	if fromInviter != "" {
		return fromInviter
	}
	base := s.Name
	if base == "" {
		base = strings.TrimPrefix(strings.TrimPrefix(s.BaseURL, "https://"), "http://")
		base, _, _ = strings.Cut(base, ":") // drop a port
	}
	slug := strings.Trim(slugRE.ReplaceAllString(strings.ToLower(base), "-"), "-.")
	if len(slug) > 32 {
		slug = slug[:32]
	}
	if slug == "" {
		return "vault"
	}
	return slug
}
