package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

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
	domain    = "vault.example.test"
	fakeValue = "sk_test_FAKE_EXAMPLE"
)

type fakeIDP struct{ byCode map[string]auth.Identity }

func (f *fakeIDP) Name() string { return "google" }
func (f *fakeIDP) AuthURL(state, nonce, verifier string) string {
	return "https://idp.test/?state=" + state
}
func (f *fakeIDP) Exchange(_ context.Context, code, _, _ string) (auth.Identity, error) {
	id, ok := f.byCode[code]
	if !ok {
		return auth.Identity{}, errors.New("bad code")
	}
	return id, nil
}

type env struct {
	t      *testing.T
	p      storage.Provider
	srv    *api.Server
	auth   *auth.Service
	tokens *auth.Tokens
	ids    *identity.Service
	log    *audit.Log
	idp    *fakeIDP
	logs   *bytes.Buffer
	clock  atomic.Int64 // unix seconds offset added to now
	ipSeq  atomic.Int64
}

func setup(t *testing.T, p storage.Provider) *env {
	e := &env{t: t, p: p, idp: &fakeIDP{map[string]auth.Identity{}}, logs: &bytes.Buffer{}}
	e.log = audit.New(p)
	e.tokens = auth.NewTokens(p)
	kf, _ := keys.GenerateMasterKey(1)
	kp, _ := keys.ParseMasterKeys(kf)
	var err error
	e.auth, err = auth.NewService(p, e.log, e.tokens, e.idp, kp, auth.Config{RPID: domain, RPOrigin: "https://" + domain, Issuer: "kuukura"})
	if err != nil {
		t.Fatal(err)
	}
	e.ids = identity.New(p, e.log, e.tokens)
	e.srv = api.New(api.Deps{
		Secrets: secrets.New(p, kp, e.log), Admin: access.NewAdmin(p, e.log), Identity: e.ids, Auth: e.auth, Tokens: e.tokens,
		Audit: e.log, Storage: p, BaseURL: "https://" + domain, Log: slog.New(slog.NewJSONHandler(e.logs, nil)),
		Now: func() time.Time { return time.Now().Add(time.Duration(e.clock.Load()) * time.Second) },
	})
	return e
}

type resp struct {
	*httptest.ResponseRecorder
}

func (r resp) json() map[string]any {
	var m map[string]any
	_ = json.Unmarshal(r.Body.Bytes(), &m)
	return m
}

func (e *env) do(method, path, token string, body any, hdr ...string) resp {
	var rd *bytes.Reader
	if s, ok := body.(string); ok {
		rd = bytes.NewReader([]byte(s))
	} else {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	// the proxy (private range, trusted for forwarded headers) reports a distinct client IP per call unless a test pins one
	req.RemoteAddr = "10.0.0.2:1234"
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", 1+e.ipSeq.Add(1)%250))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "IP" {
			req.Header.Set("X-Forwarded-For", hdr[i+1])
		} else if hdr[i+1] == "-" {
			req.Header.Del(hdr[i])
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	return resp{rec}
}

// onboard runs invite -> Google -> passkey enrollment -> CLI code exchange and returns a session.
func (e *env) onboard(invite, email string) (string, *authtest.Authenticator) {
	e.t.Helper()
	ctx := e.t.Context()
	sum := "v" + strings.Repeat("v", 42)
	hash := sha256b64(sum)
	u, err := e.auth.StartLogin(invite, auth.CLIParams{Port: 53682, Challenge: hash, State: "s"})
	if err != nil {
		e.t.Fatal(err)
	}
	pu, _ := url.Parse(u)
	code := uuid.NewString()
	e.idp.byCode[code] = auth.Identity{Subject: "sub-" + email, Email: email, EmailVerified: true}
	pd, err := e.auth.Callback(ctx, pu.Query().Get("state"), code, "203.0.113.9")
	if err != nil {
		e.t.Fatal(err)
	}
	in, err := e.tokens.Validate(ctx, pd.Token)
	if err != nil {
		e.t.Fatal(err)
	}
	dev := &authtest.Authenticator{RPID: domain, Origin: "https://" + domain}
	opts, err := e.auth.BeginPasskeyRegistration(ctx, in)
	if err != nil {
		e.t.Fatal(err)
	}
	ob, _ := json.Marshal(opts)
	res, err := e.auth.FinishPasskeyRegistration(ctx, in, dev.Register(e.t, ob, true), "203.0.113.9")
	if err != nil {
		e.t.Fatal(err)
	}
	ru, _ := url.Parse(res.Redirect)
	iss, err := e.auth.ExchangeCode(ctx, ru.Query().Get("code"), sum)
	if err != nil {
		e.t.Fatal(err)
	}
	return iss.Raw, dev
}

func (e *env) admin() (string, *authtest.Authenticator) {
	inv, err := e.ids.BootstrapAdmin(e.t.Context(), "root@example.test")
	if err != nil {
		e.t.Fatal(err)
	}
	return e.onboard(inv.Token, "root@example.test")
}

// member invites a person through the API as admin, and onboards them.
func (e *env) member(admin, email string) (string, *authtest.Authenticator) {
	r := e.do("POST", "/workspace/invites", admin, map[string]any{"email": email})
	if r.Code != 201 {
		e.t.Fatalf("invite: %d %s", r.Code, r.Body)
	}
	link, _ := url.Parse(r.json()["link"].(string))
	return e.onboard(link.Query().Get("token"), email)
}

func (e *env) stepUp(token string, dev *authtest.Authenticator, purpose, subject string) string {
	e.t.Helper()
	r := e.do("POST", "/auth/stepup", token, map[string]string{"purpose": purpose, "subject": subject})
	if r.Code != 201 {
		e.t.Fatalf("stepup start: %d %s", r.Code, r.Body)
	}
	id := r.json()["id"].(string)
	b := e.do("POST", "/stepup/"+id+"/begin", "", nil)
	if b.Code != 200 {
		e.t.Fatalf("stepup begin: %d %s", b.Code, b.Body)
	}
	f := e.do("POST", "/stepup/"+id+"/finish", "", string(dev.Assert(e.t, b.Body.Bytes(), true)))
	if f.Code != 204 {
		e.t.Fatalf("stepup finish: %d %s", f.Code, f.Body)
	}
	if d := e.do("GET", "/auth/stepup/"+id, token, nil); d.json()["done"] != true {
		e.t.Fatal("poll must report done")
	}
	return id
}

func (e *env) problem(r resp, status int, code string) {
	e.t.Helper()
	// the headers that were really sent with the response, not the map a handler may still change afterwards
	ct := r.Result().Header.Get("Content-Type")
	if r.Code != status || !strings.HasPrefix(ct, "application/problem+json") {
		e.t.Fatalf("want %d problem+json, got %d %s %s", status, r.Code, ct, r.Body)
	}
	m := r.json()
	if m["code"] != code || m["status"] != float64(status) || m["title"] == "" || m["type"] == "" || m["instance"] == "" {
		e.t.Fatalf("want code %s, got %v", code, m)
	}
}

func sha256b64(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
