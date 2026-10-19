package api

import (
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/auth"
)

// The only web pages: invite acceptance, second factor, passkey/TOTP enrollment, step-up.
// Strict CSP: one nonce-protected inline script, no external resources.

const pageCSS = `body{font:16px/1.5 system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem;color:#111}
button,input{font:inherit;padding:.6rem .9rem;margin:.25rem 0;display:block;width:100%;box-sizing:border-box}
button{cursor:pointer}p.m{color:#b00}code{word-break:break-all}.hide{display:none}
@media(prefers-color-scheme:dark){body{background:#111;color:#eee}}`

const pageJS = `
const $=i=>document.getElementById(i),B=document.body.dataset;
const msg=t=>{$('m').textContent=t};
async function post(p,b,t){const r=await fetch(p,{method:'POST',headers:{'Content-Type':'application/json',...(t?{Authorization:'Bearer '+t}:{})},body:JSON.stringify(b||{})});
 if(!r.ok)throw 0;return r.status===204?{}:r.json()}
function finish(j){if(j.recovery_codes){$('codes').textContent=j.recovery_codes.join('\n');$('rc').classList.remove('hide');$('go').onclick=()=>{location=j.redirect}}else location=j.redirect}
const run=f=>async()=>{try{await f()}catch(e){msg('That did not work. Try again.')}};
if(B.mode==='mfa'||B.mode==='enroll'){const base='/auth/'+B.mode;
 $('pk').onclick=run(async()=>{const o=await post(base+'/passkey/begin',0,B.t);
  if(B.mode==='enroll'){const c=await navigator.credentials.create({publicKey:PublicKeyCredential.parseCreationOptionsFromJSON(o.publicKey)});finish(await post(base+'/passkey/finish',c.toJSON(),B.t))}
  else{const a=await navigator.credentials.get({publicKey:PublicKeyCredential.parseRequestOptionsFromJSON(o.publicKey)});finish(await post(base+'/passkey/finish',a.toJSON(),B.t))}});
 if(B.mode==='mfa'){$('f').onsubmit=e=>{e.preventDefault();run(async()=>finish(await post(base+'/totp',{code:$('code').value},B.t)))()};
  $('r').onsubmit=e=>{e.preventDefault();run(async()=>finish(await post(base+'/recovery',{code:$('rcode').value},B.t)))()}}
 else{$('tb').onclick=run(async()=>{const j=await post(base+'/totp/begin',0,B.t);$('sec').textContent=j.secret;$('tf').classList.remove('hide')});
  $('tf').onsubmit=e=>{e.preventDefault();run(async()=>finish(await post(base+'/totp/confirm',{code:$('code').value},B.t)))()}}}
if(B.mode==='stepup'){$('pk').onclick=run(async()=>{const o=await post('/stepup/'+B.id+'/begin');
 const a=await navigator.credentials.get({publicKey:PublicKeyCredential.parseRequestOptionsFromJSON(o.publicKey)});
 await post('/stepup/'+B.id+'/finish',a.toJSON());msg('Confirmed. You can go back to your terminal.')})}
`

var pageTmpl = template.Must(template.New("p").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>{{.Title}}</title><style nonce="{{.Nonce}}">` + pageCSS + `</style></head>
<body data-mode="{{.Mode}}" data-t="{{.Token}}" data-id="{{.ID}}"><h1>{{.Title}}</h1>
{{if eq .Mode "invite"}}<p>You have been invited to this vault.</p><p><a href="{{.Link}}">Continue with Google</a></p>
{{else if eq .Mode "mfa"}}<button id="pk">Use a passkey</button>
<form id="f"><label>Authenticator code<input id="code" inputmode="numeric" autocomplete="one-time-code"></label><button>Verify</button></form>
<form id="r"><label>Recovery code<input id="rcode" autocomplete="off"></label><button>Use recovery code</button></form>
{{else if eq .Mode "enroll"}}<p>Set up a second step for sign-in.</p><button id="pk">Register a passkey</button>
<button id="tb">Use an authenticator app instead</button>
<form id="tf" class="hide"><p>Add this key to your authenticator app:</p><code id="sec"></code>
<label>Code<input id="code" inputmode="numeric" autocomplete="one-time-code"></label><button>Confirm</button></form>
{{else if eq .Mode "stepup"}}<p>Confirm it is you to continue in your terminal.</p><button id="pk">Confirm</button>
{{else if eq .Mode "done"}}<p>All set. Return to your terminal and run <code>ku login</code>.</p>
{{else}}<p>Login failed. Start again from your terminal with <code>ku login</code>.</p>{{end}}
<div id="rc" class="hide"><p>Save these recovery codes now. Each works once and they are not shown again.</p><pre id="codes"></pre><button id="go">Continue</button></div>
<p class="m" id="m"></p>
<script nonce="{{.Nonce}}">` + pageJS + `</script></body></html>`))

type pageData struct {
	Title, Mode, Token, ID, Nonce string
	Link                          string
}

func (s *Server) page(c echo.Context, status int, d pageData) error {
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	d.Nonce = base64.RawURLEncoding.EncodeToString(n)
	h := c.Response().Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+d.Nonce+"'; style-src 'nonce-"+d.Nonce+"'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	h.Set("Content-Type", "text/html; charset=utf-8")
	c.Response().WriteHeader(status)
	return pageTmpl.Execute(c.Response(), d)
}

func (s *Server) failPage(c echo.Context) error {
	return s.page(c, http.StatusUnauthorized, pageData{Title: "Login failed", Mode: "fail"})
}

func (s *Server) donePage(c echo.Context) error {
	return s.page(c, http.StatusOK, pageData{Title: "Done", Mode: "done"})
}

func (s *Server) factorPage(c echo.Context, p auth.Pending) error {
	title := "Confirm it is you"
	if p.Mode == "enroll" {
		title = "Set up sign-in"
	}
	return s.page(c, http.StatusOK, pageData{Title: title, Mode: p.Mode, Token: p.Token})
}

func (s *Server) stepUpPage(c echo.Context) error {
	return s.page(c, http.StatusOK, pageData{Title: "Confirm", Mode: "stepup", ID: c.QueryParam("id")})
}

func (s *Server) invitePage(c echo.Context) error {
	tok := c.QueryParam("token")
	if email, err := s.Tokens.PeekInvite(c.Request().Context(), tok); err != nil || email == "" {
		return s.page(c, http.StatusNotFound, pageData{Title: "Invite not valid", Mode: "fail"})
	}
	link := ("/auth/login?invite=" + url.QueryEscape(tok))
	return s.page(c, http.StatusOK, pageData{Title: "Join the vault", Mode: "invite", Link: link})
}
