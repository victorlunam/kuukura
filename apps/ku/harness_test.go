package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/victorlunam/kuukura/apps/ku-server/api"
	"github.com/victorlunam/kuukura/internal/access"
	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/auth"
	"github.com/victorlunam/kuukura/internal/auth/authtest"
	"github.com/victorlunam/kuukura/internal/identity"
	"github.com/victorlunam/kuukura/internal/keys"
	"github.com/victorlunam/kuukura/internal/secrets"
	"github.com/victorlunam/kuukura/internal/storage"
)

const (
	testDomain = "vault.example.test"
	fakeValue  = "sk_test_FAKE_EXAMPLE"
)

type memStore struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memStore) Get(p string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.m[p]; ok {
		return t, nil
	}
	return "", errNoToken
}
func (s *memStore) Set(p, t string) error { s.mu.Lock(); s.m[p] = t; s.mu.Unlock(); return nil }
func (s *memStore) Delete(p string) error { s.mu.Lock(); delete(s.m, p); s.mu.Unlock(); return nil }

// world is a real server (full API stack over TLS) plus fake browser, Keychain and home.
type world struct {
	t       *testing.T
	p       storage.Provider
	srv     *httptest.Server
	auth    *auth.Service
	tokens  *auth.Tokens
	ids     *identity.Service
	log     *audit.Log
	idp     *authtest.IDP
	store   *memStore
	home    string
	stepUps int                                // confirmations (passkey or authenticator code) performed by the fake browser
	devs    map[string]*authtest.Authenticator // by principal email
	emails  map[string]string                  // session token -> email
	now     time.Time
	mu      sync.Mutex

	totpSecrets map[string]string  // authenticator-app secrets by principal email (users enrolled with TOTP only)
	altStore    tokenStore         // a test can swap the in-memory Keychain for the real session store
	opener      func(string) error // a test can replace the fake browser
	skew        time.Duration
}

func newWorld(t *testing.T, p storage.Provider) *world {
	w := &world{t: t, p: p, idp: authtest.NewIDP(), store: &memStore{m: map[string]string{}},
		home: t.TempDir(), devs: map[string]*authtest.Authenticator{}, emails: map[string]string{}, now: time.Now()}
	w.log = audit.New(p)
	w.tokens = auth.NewTokens(p)
	// the service's clock: real time plus a skew the fake browser advances by one TOTP step per confirmation, because
	// an authenticator code works once (a real person waits for the next code)
	w.tokens.Now = func() time.Time { w.mu.Lock(); defer w.mu.Unlock(); return time.Now().Add(w.skew) }
	w.totpSecrets = map[string]string{}
	kf, _ := keys.GenerateMasterKey(1)
	kp, _ := keys.ParseMasterKeys(kf)
	var err error
	w.auth, err = auth.NewService(p, w.log, w.tokens, w.idp, kp, auth.Config{RPID: testDomain, RPOrigin: "https://" + testDomain, Issuer: "kuukura"})
	if err != nil {
		t.Fatal(err)
	}
	w.ids = identity.New(p, w.log, w.tokens)
	// The links the server hands out must point at the server the profile names, as they do in a real deployment:
	// the CLI opens nothing else. So the public origin is the test server's own address.
	w.srv = httptest.NewUnstartedServer(nil)
	srv := api.New(api.Deps{
		Secrets: secrets.New(p, kp, w.log), Admin: access.NewAdmin(p, w.log), Identity: w.ids, Auth: w.auth, Tokens: w.tokens,
		Audit: w.log, Storage: p, BaseURL: "https://" + w.srv.Listener.Addr().String(),
		Now: func() time.Time { w.mu.Lock(); defer w.mu.Unlock(); w.now = w.now.Add(10 * time.Second); return w.now }, // limits never bite
	})
	w.srv.Config.Handler = srv.Handler()
	w.srv.StartTLS()
	t.Cleanup(w.srv.Close)
	return w
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// onboardTOTP is onboard for a user whose only second step is an authenticator app.
func (w *world) onboardTOTP(invite, email string) string {
	w.t.Helper()
	verifier := strings.Repeat("v", 43)
	u, err := w.auth.StartLogin(invite, auth.CLIParams{Port: 53682, Challenge: sha(verifier), State: uuid.NewString()}) // a CLI picks a fresh state per run: a link works once
	if err != nil {
		w.t.Fatal(err)
	}
	pu, _ := url.Parse(u)
	code := uuid.NewString()
	w.idp.Allow(code, auth.Identity{Subject: "sub-" + email, Email: email, EmailVerified: true})
	pd, err := w.auth.Callback(w.t.Context(), pu.Query().Get("state"), code, "203.0.113.9")
	if err != nil {
		w.t.Fatal(err)
	}
	in, _ := w.tokens.Validate(w.t.Context(), pd.Token)
	secret, _, err := w.auth.BeginTOTP(w.t.Context(), in)
	if err != nil {
		w.t.Fatal(err)
	}
	first, _ := totp.GenerateCode(secret, w.tokens.Now())
	res, err := w.auth.ConfirmTOTP(w.t.Context(), in, first, "203.0.113.9")
	if err != nil {
		w.t.Fatal(err)
	}
	ru, _ := url.Parse(res.Redirect)
	iss, err := w.auth.ExchangeCode(w.t.Context(), ru.Query().Get("code"), verifier)
	if err != nil {
		w.t.Fatal(err)
	}
	w.totpSecrets[email] = secret
	return iss.Raw
}

// onboard creates an enrolled user with a passkey (invite -> Google -> passkey) and returns a session token.
func (w *world) onboard(invite, email string) string {
	w.t.Helper()
	verifier := strings.Repeat("v", 43)
	u, err := w.auth.StartLogin(invite, auth.CLIParams{Port: 53682, Challenge: sha(verifier), State: uuid.NewString()}) // a CLI picks a fresh state per run: a link works once
	if err != nil {
		w.t.Fatal(err)
	}
	pu, _ := url.Parse(u)
	code := uuid.NewString()
	w.idp.Allow(code, auth.Identity{Subject: "sub-" + email, Email: email, EmailVerified: true})
	pd, err := w.auth.Callback(w.t.Context(), pu.Query().Get("state"), code, "203.0.113.9")
	if err != nil {
		w.t.Fatal(err)
	}
	in, _ := w.tokens.Validate(w.t.Context(), pd.Token)
	dev := &authtest.Authenticator{RPID: testDomain, Origin: "https://" + testDomain}
	opts, err := w.auth.BeginPasskeyRegistration(w.t.Context(), in)
	if err != nil {
		w.t.Fatal(err)
	}
	ob, _ := json.Marshal(opts)
	res, err := w.auth.FinishPasskeyRegistration(w.t.Context(), in, dev.Register(w.t, ob, true), "203.0.113.9")
	if err != nil {
		w.t.Fatal(err)
	}
	ru, _ := url.Parse(res.Redirect)
	iss, err := w.auth.ExchangeCode(w.t.Context(), ru.Query().Get("code"), verifier)
	if err != nil {
		w.t.Fatal(err)
	}
	w.devs[email] = dev
	w.emails[iss.Raw] = email
	return iss.Raw
}

func (w *world) admin() string {
	inv, err := w.ids.BootstrapAdmin(w.t.Context(), "root@example.test")
	if err != nil {
		w.t.Fatal(err)
	}
	return w.onboard(inv.Token, "root@example.test")
}

func (w *world) api(token, method, path string, body any, hdr ...string) (int, map[string]any) {
	w.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, w.srv.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := w.srv.Client().Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func (w *world) member(admin, email string) string {
	code, m := w.api(admin, "POST", "/workspace/invites", map[string]any{"email": email})
	if code != 201 {
		w.t.Fatalf("invite: %d %v", code, m)
	}
	link, _ := url.Parse(m["link"].(string))
	return w.onboard(link.Query().Get("token"), email)
}

func (w *world) grant(admin, who, perm string, tags ...string) {
	if code, m := w.api(admin, "POST", "/workspace/grants", map[string]any{"subject": who, "permission": perm, "tags": tags}); code != 201 {
		w.t.Fatalf("grant: %d %v", code, m)
	}
}

// browser plays the part of the user's browser for login and step-up pages.
func (w *world) browser(raw string) error {
	hc := &http.Client{Transport: w.srv.Client().Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	u, _ := url.Parse(raw)
	post := func(path, token string, body []byte) (int, []byte) {
		req, _ := http.NewRequest("POST", w.srv.URL+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := hc.Do(req)
		if err != nil {
			w.t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	// The person at this browser is the one whose terminal opened the link: the profile name in the link finds
	// their session. Their devices are keyed by their email, and an added one as "<email>#added-N". Only their own
	// devices are used, so a server that accepted somebody else's credential would fail the test, not pass it.
	var email string
	if profile := u.Query().Get("profile"); profile != "" {
		if tok, err := w.sessionStore().Get(profile); err == nil {
			if in, err := w.tokens.Validate(w.t.Context(), tok); err == nil {
				_ = w.p.DB().QueryRow(w.p.Rebind(`SELECT email FROM principals WHERE id = ?`), in.PrincipalID).Scan(&email)
			}
		}
	}
	mine := func(k string) bool { return email != "" && (k == email || strings.HasPrefix(k, email+"#")) }
	switch {
	case u.Path == "/stepup":
		id := u.Query().Get("id")
		_, opts := post("/stepup/"+id+"/begin", "", nil)
		for k, dev := range w.devs {
			if !mine(k) {
				continue
			}
			if code, _ := post("/stepup/"+id+"/finish", "", dev.Assert(w.t, opts, true)); code == 204 {
				w.stepUps++
				return nil
			}
			_, opts = post("/stepup/"+id+"/begin", "", nil)
		}
		// or an authenticator app: each confirmation needs a code from a new 30-second step
		for k, secret := range w.totpSecrets {
			if !mine(k) {
				continue
			}
			w.mu.Lock()
			w.skew += 31 * time.Second
			w.mu.Unlock()
			code, _ := totp.GenerateCode(secret, w.tokens.Now())
			if status, _ := post("/stepup/"+id+"/totp", "", []byte(`{"code":"`+code+`"}`)); status == 204 {
				w.stepUps++
				return nil
			}
		}
		return errors.New("no device could confirm")
	case u.Path == "/account/add":
		// the link from `ku account factor add`: a card first (opening it spends nothing), then its button (go=1)
		// opens the short session in which the browser registers the new factor
		card, err := hc.Get(w.srv.URL + "/account/add?" + u.RawQuery)
		if err != nil {
			w.t.Fatal(err)
		}
		cb, _ := io.ReadAll(card.Body)
		card.Body.Close()
		if card.StatusCode != 200 || !strings.Contains(string(cb), `data-mode="addask"`) {
			return errors.New("this link is not valid")
		}
		page, err := hc.Get(w.srv.URL + "/account/add?" + u.RawQuery + "&go=1")
		if err != nil {
			w.t.Fatal(err)
		}
		pb, _ := io.ReadAll(page.Body)
		page.Body.Close()
		tok := regexp.MustCompile(`data-t="([^"]+)"`).FindStringSubmatch(string(pb))
		if page.StatusCode != 200 || tok == nil || !strings.Contains(string(pb), `data-mode="add"`) {
			return errors.New("this link is not valid")
		}
		if email == "" {
			w.t.Fatal("the add link carries no profile name that finds the person's session")
		}
		name := fmt.Sprintf("%s#added-%d", email, len(w.devs)+len(w.totpSecrets))
		if strings.Contains(string(pb), `id="pk"`) {
			_, opts := post("/auth/enroll/passkey/begin", tok[1], nil)
			dev := &authtest.Authenticator{RPID: testDomain, Origin: "https://" + testDomain}
			if code, b := post("/auth/enroll/passkey/finish", tok[1], dev.Register(w.t, opts, true)); code != 200 || !strings.Contains(string(b), "/account/added") || strings.Contains(string(b), "recovery_codes") {
				w.t.Fatalf("add passkey: %d %s", code, b)
			}
			w.devs[name] = dev
			return nil
		}
		code, b := post("/auth/enroll/totp/begin", tok[1], nil)
		var begin struct{ Secret string }
		if err := json.Unmarshal(b, &begin); code != 200 || err != nil {
			w.t.Fatalf("add totp begin: %d %s", code, b)
		}
		w.mu.Lock()
		w.skew += 31 * time.Second
		w.mu.Unlock()
		c, _ := totp.GenerateCode(begin.Secret, w.tokens.Now())
		if code, b := post("/auth/enroll/totp/confirm", tok[1], []byte(`{"code":"`+c+`"}`)); code != 200 || strings.Contains(string(b), "recovery_codes") {
			w.t.Fatalf("add totp: %d %s", code, b)
		}
		w.totpSecrets[name] = begin.Secret
		return nil
	case u.Path == "/auth/login":
		q := u.Query()
		// the printed link opens the sign-in card; the person then presses "Continue with Google" (go=1)
		card, err := hc.Get(w.srv.URL + "/auth/login?" + u.RawQuery)
		if err != nil || card.StatusCode != 200 {
			w.t.Fatalf("sign-in card: %v %v", err, card)
		}
		cardBody, _ := io.ReadAll(card.Body)
		card.Body.Close()
		if !strings.Contains(string(cardBody), "Continue with Google") || !strings.Contains(string(cardBody), "<small>"+q.Get("cli_profile")+"</small>") {
			w.t.Fatalf("the sign-in card shows the button and the profile name")
		}
		resp, err := hc.Get(w.srv.URL + "/auth/login?" + u.RawQuery + "&go=1")
		if err != nil || resp.StatusCode != 302 {
			w.t.Fatalf("login start: %v %v", err, resp)
		}
		idp, _ := url.Parse(resp.Header.Get("Location"))
		code := uuid.NewString()
		w.idp.Allow(code, auth.Identity{Subject: "sub-root@example.test", Email: "root@example.test", EmailVerified: true})
		cb, err := hc.Get(w.srv.URL + "/auth/callback?state=" + idp.Query().Get("state") + "&code=" + code)
		if err != nil {
			w.t.Fatal(err)
		}
		page, _ := io.ReadAll(cb.Body)
		cb.Body.Close()
		tok := regexp.MustCompile(`data-t="([^"]+)"`).FindStringSubmatch(string(page))
		if cb.StatusCode != 200 || tok == nil || !strings.Contains(string(page), `data-mode="mfa"`) {
			w.t.Fatalf("callback page: %d", cb.StatusCode)
		}
		_, opts := post("/auth/mfa/passkey/begin", tok[1], nil)
		dev := w.devs["root@example.test"]
		code2, fin := post("/auth/mfa/passkey/finish", tok[1], dev.Assert(w.t, opts, true))
		if code2 != 200 {
			w.t.Fatalf("mfa finish: %d %s", code2, fin)
		}
		var r struct{ Redirect string }
		_ = json.Unmarshal(fin, &r)
		ru, _ := url.Parse(r.Redirect)
		if ru.Host != "127.0.0.1:"+q.Get("cli_port") {
			w.t.Fatalf("redirect goes to %s", ru.Host)
		}
		resp2, err := http.Get(r.Redirect)
		if err != nil {
			w.t.Fatal(err)
		}
		resp2.Body.Close()
		return nil
	}
	return errors.New("unexpected url " + raw)
}

type result struct {
	code        int
	out, errOut string
}

// ku runs the CLI against the world. The profile and token are set up by loginAs.
func (w *world) ku(stdin string, tty bool, env map[string]string, args ...string) result {
	w.t.Helper()
	var out, errb bytes.Buffer
	a := &app{
		in: strings.NewReader(stdin), out: &out, err: &errb,
		getenv: func(k string) string { return env[k] }, store: w.sessionStore(),
		http: &http.Client{Transport: w.srv.Client().Transport, Timeout: 20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		openURL: w.browser, isTTY: tty, home: w.home, cwd: w.home, poll: 5 * time.Millisecond,
	}
	if tty { // without a terminal the value comes from stdin and nothing prompts
		a.readSecret = func(string) (string, error) { return fakeValue, nil }
	}
	if w.opener != nil {
		a.openURL = w.opener
	}
	if cwd, ok := env["CWD"]; ok {
		a.cwd = cwd
	}
	code := a.run(args)
	return result{code, out.String(), errb.String()}
}

// loginAs gives the CLI profile "default" pointing at the test server with the given session.
func (w *world) loginAs(token string) {
	w.t.Helper()
	if _, err := os.Stat(filepath.Join(w.home, ".config", "kuukura", "config.toml")); err != nil {
		if res := w.ku("", false, nil, "profile", "add", "default", "--url", w.srv.URL); res.code != 0 {
			w.t.Fatal(res.errOut)
		}
	}
	_ = w.store.Set("default", token)
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func (w *world) sessionStore() tokenStore {
	if w.altStore != nil {
		return w.altStore
	}
	return w.store
}

func readFile(p string) (string, error) { b, err := os.ReadFile(p); return string(b), err }
