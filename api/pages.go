package api

import (
	"crypto/rand"
	"embed"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/auth"
)

// The only web pages: the sign-in and invite cards, second factor (sign-in), first enrollment, adding a factor to
// an active account, the step-up confirmation, and their result pages (done, added, failures).
// Everything is embedded (templates, CSS, JS, SVG art): no external resources and a strict CSP with one nonce.

//go:embed web
var webFS embed.FS

var pageTmpl = template.Must(template.ParseFS(webFS, "web/page.html"))

func webFile(name string) string {
	b, err := webFS.ReadFile("web/" + name)
	if err != nil {
		panic(err) // embedded at build time
	}
	return string(b)
}

// The static pieces are trusted, embedded files (not user input), so they are marked safe once at startup.
var (
	pageCSS    = template.CSS(webFile("style.css"))        // #nosec G203 -- embedded file
	pageJS     = template.JS(webFile("app.js"))            // #nosec G203 -- embedded file
	pageSprite = template.HTML(webFile("sprite.svg"))      // #nosec G203 -- embedded file
	pageMark   = template.HTML(webFile("assets/mark.svg")) // #nosec G203 -- embedded file
)

// styleBlock matches the <style> each art file carries so it also renders on its own; inside a page the
// colors come from the page's CSS variables instead (a <style> in the page would need the CSP nonce).
var styleBlock = regexp.MustCompile(`(?s)\s*<style>.*?</style>`)

func art(name string) template.HTML {
	return template.HTML(styleBlock.ReplaceAllString(webFile("art/"+name+".svg"), "")) // #nosec G203 -- embedded file
}

type pageData struct {
	Title, Mode, Token, ID, Nonce string
	Link, Email, Detail, Suggest  string
	Add                           string // mode "add": passkey or totp
	Ask                           string // mode "stepup": what is being confirmed
	Default                       string // the account's default factor kind: its method is offered first
	Label, Origin                 string
	Step                          int
	Hint                          bool // show the `ku login` command on a result page
	HasPasskey, HasTOTP           bool // second-step methods this account has (mfa page)
	Art, ArtDone                  template.HTML
	CSS                           template.CSS
	JS                            template.JS
	Sprite, Mark                  template.HTML
}

func (s *Server) page(c echo.Context, status int, d pageData) error {
	d.Nonce = rand.Text()
	d.CSS, d.JS, d.Sprite, d.Mark = pageCSS, pageJS, pageSprite, pageMark
	d.Origin = s.BaseURL
	if d.Label == "" { // the CLI's profile name when it sent one, else the instance name, else the host
		d.Label = s.Name
	}
	if d.Label == "" {
		d.Label = strings.TrimPrefix(strings.TrimPrefix(s.BaseURL, "https://"), "http://")
	}
	if d.Mode == "stepup" {
		d.ArtDone = art("done")
	}
	h := c.Response().Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+d.Nonce+"'; style-src 'nonce-"+d.Nonce+"'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	h.Set("Content-Type", "text/html; charset=utf-8")
	c.Response().WriteHeader(status)
	return pageTmpl.Execute(c.Response(), d)
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

func (s *Server) donePage(c echo.Context) error {
	return s.page(c, http.StatusOK, pageData{Title: "You're all set", Mode: "done", Art: art("done"), Step: 3,
		Suggest: s.suggestProfile(auth.CleanLabel(c.QueryParam("profile")))})
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

func (s *Server) factorPage(c echo.Context, p auth.Pending) error {
	if p.Mode == "enroll" {
		return s.page(c, http.StatusOK, pageData{Title: "Secure your account", Mode: "enroll", Token: p.Token, Art: art("passkey"), Step: 2, Label: p.Profile})
	}
	return s.page(c, http.StatusOK, pageData{Title: "Confirm it's you", Mode: "mfa", Token: p.Token, Art: art("shield"), Label: p.Profile,
		HasPasskey: p.Passkey, HasTOTP: p.TOTP, Default: p.Default})
}

// stepUpAsk words what a confirmation is for, from its purpose and subject. The subject is the person's own
// selector (or a factor kind or id), shown as plain text: the template escapes it.
func stepUpAsk(purpose, subject string) string {
	switch purpose {
	case purposeReveal:
		return "Reveal " + subject
	case purposeRun:
		return "Run with " + subject
	case purposeAuthorizeOff:
		return "Turn off confirmation for " + subject
	case purposeFactorAdd:
		if subject == "totp" {
			return "Add an authenticator app"
		}
		return "Add a passkey"
	case purposeFactorRemove:
		return "Remove a second step"
	}
	return ""
}

func (s *Server) stepUpPage(c echo.Context) error {
	id := c.QueryParam("id")
	r, err := s.Auth.LookupStepUp(c.Request().Context(), id)
	if err != nil || !r.Passkey && !r.TOTP { // unknown, expired or already used request
		return s.page(c, http.StatusNotFound, pageData{
			Title: "This confirmation is no longer valid", Mode: "fail", Art: art("alert"),
			Detail: "It may have expired or already been used. Run the command in your terminal again to get a new one.",
		})
	}
	return s.page(c, http.StatusOK, pageData{Title: "Confirm it's you", Mode: "stepup", ID: id, Art: art("confirm"),
		Label: auth.CleanLabel(c.QueryParam("profile")), HasPasskey: r.Passkey, HasTOTP: r.TOTP, Default: r.Default,
		Ask: stepUpAsk(r.Purpose, r.Subject)})
}

func (s *Server) invitePage(c echo.Context) error {
	tok := c.QueryParam("token")
	email, err := s.Tokens.PeekInvite(c.Request().Context(), tok)
	if err != nil || email == "" {
		return s.page(c, http.StatusNotFound, pageData{
			Title: "This invite is not valid", Mode: "fail", Art: art("alert"),
			Detail: "It may have expired or already been used. Ask your admin for a new one.",
		})
	}
	link := "/auth/login?go=1&invite=" + url.QueryEscape(tok)   // this page already is the button page
	if p := auth.CleanLabel(c.QueryParam("profile")); p != "" { // the inviter's profile name, carried to the "all set" page
		link += "&cli_profile=" + p
	}
	return s.page(c, http.StatusOK, pageData{
		Title: "You're invited", Mode: "invite", Art: art("vault-empty"), Step: 1,
		Email: email, Link: link,
	})
}

// ---- static brand assets ----

var assetNames = map[string]bool{"logo.svg": true, "mark.svg": true, "favicon.svg": true, "banner.svg": true}

// asset serves an embedded SVG. They are sandboxed by CSP in case they are opened directly.
func (s *Server) asset(c echo.Context) error {
	name := c.Param("name")
	if name == "" {
		name = "favicon.svg"
	}
	if !assetNames[name] {
		return &apiError{404, "not-found", "Not found", "", nil, nil}
	}
	h := c.Response().Header()
	h.Set("Cache-Control", "public, max-age=86400")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	return c.Blob(http.StatusOK, "image/svg+xml", []byte(webFile("assets/"+name)))
}
