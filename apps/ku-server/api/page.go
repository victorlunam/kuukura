package api

import (
	"crypto/rand"
	"embed"
	"html/template"
	"regexp"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/packages/brand"
)

// The only web pages: the sign-in and invite cards, second factor (sign-in), first enrollment, adding a factor to
// an active account, the step-up confirmation, and their result pages (done, added, failures).
// Everything is embedded (templates, CSS, JS, SVG art): no external resources and a strict CSP with one nonce.
// The page, CSS and JS live here; the brand files (art, sprite, logos) come from packages/brand.

//go:embed web
var webFS embed.FS

var pageTmpl = template.Must(template.New("page.html").Funcs(template.FuncMap{"email": emailHTML}).ParseFS(webFS, "web/page.html"))

// emailHTML shows an address in bold, marked so a CDN's email obfuscation (Cloudflare's) leaves it alone: its
// decoding script is blocked by our CSP, which would leave "[email protected]" on the page. html/template strips
// comments from templates, so the markers are added here, around the escaped address.
func emailHTML(addr string) template.HTML {
	return template.HTML("<!--email_off--><b>" + template.HTMLEscapeString(addr) + "</b><!--/email_off-->") // #nosec G203 -- escaped above
}

func webFile(name string) string { return embedded(webFS, "web/"+name) }

func brandFile(name string) string { return embedded(brand.FS, name) }

func embedded(fsys embed.FS, name string) string {
	b, err := fsys.ReadFile(name)
	if err != nil {
		panic(err) // embedded at build time
	}
	return string(b)
}

// The static pieces are trusted, embedded files (not user input), so they are marked safe once at startup.
var (
	pageCSS    = template.CSS(webFile("style.css"))          // #nosec G203 -- embedded file
	pageJS     = template.JS(webFile("app.js"))              // #nosec G203 -- embedded file
	pageSprite = template.HTML(brandFile("sprite.svg"))      // #nosec G203 -- embedded file
	pageMark   = template.HTML(brandFile("assets/mark.svg")) // #nosec G203 -- embedded file
)

// styleBlock matches the <style> each art file carries so it also renders on its own; inside a page the
// colors come from the page's CSS variables instead (a <style> in the page would need the CSP nonce).
var styleBlock = regexp.MustCompile(`(?s)\s*<style>.*?</style>`)

func art(name string) template.HTML {
	return template.HTML(styleBlock.ReplaceAllString(brandFile("art/"+name+".svg"), "")) // #nosec G203 -- embedded file
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
