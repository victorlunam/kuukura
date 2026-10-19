package auth_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/victorlunam/kuukura/access"
	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/auth"
	"github.com/victorlunam/kuukura/auth/authtest"
	"github.com/victorlunam/kuukura/identity"
	"github.com/victorlunam/kuukura/keys"
	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

var ctx = context.Background()

const (
	rpID   = "vault.example.test"
	origin = "https://vault.example.test"
)

// fakeIDP is a stand-in for Google: codes map to identities.
type fakeIDP struct{ byCode map[string]auth.Identity }

func (f *fakeIDP) Name() string { return "google" }
func (f *fakeIDP) AuthURL(state, nonce, verifier string) string {
	return "https://idp.test/auth?state=" + state
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
	svc    *auth.Service
	tokens *auth.Tokens
	ids    *identity.Service
	log    *audit.Log
	idp    *fakeIDP
	clock  time.Time
}

func setup(t *testing.T, p storage.Provider) *env {
	e := &env{t: t, p: p, clock: time.Now().UTC(), idp: &fakeIDP{map[string]auth.Identity{}}}
	e.log = audit.New(p)
	e.tokens = auth.NewTokens(p)
	e.tokens.Now = func() time.Time { return e.clock }
	kf, _ := keys.GenerateMasterKey(1)
	kp, _ := keys.ParseMasterKeys(kf)
	var err error
	e.svc, err = auth.NewService(p, e.log, e.tokens, e.idp, kp, auth.Config{RPID: rpID, RPOrigin: origin, Issuer: "kuukura"})
	if err != nil {
		t.Fatal(err)
	}
	e.ids = identity.New(p, e.log, e.tokens)
	return e
}

type cli struct {
	verifier string
	params   auth.CLIParams
}

func newCLI() cli {
	v := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(v))
	return cli{v, auth.CLIParams{Port: 53682, Challenge: base64.RawURLEncoding.EncodeToString(sum[:]), State: "st4te"}}
}

// login runs StartLogin + Callback for an identity.
func (e *env) login(invite string, id auth.Identity) (auth.Pending, cli, error) {
	c := newCLI()
	u, err := e.svc.StartLogin(invite, c.params)
	if err != nil {
		e.t.Fatal(err)
	}
	state, _ := url.Parse(u)
	code := uuid.NewString()
	e.idp.byCode[code] = id
	pd, err := e.svc.Callback(ctx, state.Query().Get("state"), code, "203.0.113.9")
	return pd, c, err
}

func (e *env) info(raw string) auth.Info {
	e.t.Helper()
	in, err := e.tokens.Validate(ctx, raw)
	if err != nil {
		e.t.Fatal(err)
	}
	return in
}

// finishCLI follows the redirect like the CLI would and returns the session.
func (e *env) finishCLI(redirect string, c cli) (auth.Issued, error) {
	u, err := url.Parse(redirect)
	if err != nil || u.Host != "127.0.0.1:"+strconv.Itoa(c.params.Port) || u.Query().Get("state") != c.params.State {
		e.t.Fatalf("bad redirect %q", redirect)
	}
	return e.svc.ExchangeCode(ctx, u.Query().Get("code"), c.verifier)
}

func (e *env) bootstrap(email string) string {
	inv, err := e.ids.BootstrapAdmin(ctx, email)
	if err != nil {
		e.t.Fatal(err)
	}
	return inv.Token
}

func (e *env) count(q string, args ...any) int {
	var n int
	if err := e.p.DB().QueryRow(e.p.Rebind(q), args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func TestInviteTOTPEnrollmentAndLogin(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		invite := e.bootstrap("boss@example.test")
		g := auth.Identity{Subject: "sub-boss", Email: "Boss@Example.test", EmailVerified: true}

		// wrong email, unverified email, unknown identity without invite: all the same error
		if _, _, err := e.login(invite, auth.Identity{Subject: "x", Email: "other@example.test", EmailVerified: true}); !errors.Is(err, auth.ErrLogin) {
			t.Fatal("invite is bound to its email")
		}
		if _, _, err := e.login(invite, auth.Identity{Subject: "sub-boss", Email: "boss@example.test", EmailVerified: false}); !errors.Is(err, auth.ErrLogin) {
			t.Fatal("email_verified is required")
		}
		if _, _, err := e.login("", g); !errors.Is(err, auth.ErrLogin) {
			t.Fatal("no auto-registration")
		}

		pd, c, err := e.login(invite, g)
		if err != nil || pd.Mode != "enroll" {
			t.Fatalf("accept invite: %+v %v", pd, err)
		}
		if _, _, err := e.login(invite, g); !errors.Is(err, auth.ErrLogin) {
			t.Fatal("invite is single use")
		}
		in := e.info(pd.Token)
		if in.HasScope(auth.ScopeRead) {
			t.Fatal("an enrolling session cannot use the API")
		}

		secret, uri, err := e.svc.BeginTOTP(ctx, in)
		if err != nil || !strings.HasPrefix(uri, "otpauth://totp/") {
			t.Fatal(err)
		}
		if _, err := e.svc.ConfirmTOTP(ctx, in, "000000", "203.0.113.9"); !errors.Is(err, auth.ErrLogin) {
			t.Fatal("wrong code must not enroll")
		}
		code, _ := totp.GenerateCode(secret, time.Now())
		res, err := e.svc.ConfirmTOTP(ctx, in, code, "203.0.113.9")
		if err != nil || len(res.RecoveryCodes) != 10 {
			t.Fatalf("confirm: %v", err)
		}
		if e.count(`SELECT COUNT(*) FROM principals WHERE name = 'boss@example.test' AND status = 'active'`) != 1 {
			t.Fatal("principal must become active")
		}
		// the TOTP secret is encrypted at rest
		var enc []byte
		if err := p.DB().QueryRow(`SELECT encrypted_totp_secret FROM credentials WHERE kind = 'totp'`).Scan(&enc); err != nil || bytes.Contains(enc, []byte(secret)) {
			t.Fatal("totp secret must not be stored in plaintext")
		}
		if _, err := e.tokens.Validate(ctx, pd.Token); !errors.Is(err, auth.ErrInvalid) {
			t.Fatal("the enrollment session ends with the login")
		}
		sess, err := e.finishCLI(res.Redirect, c)
		if err != nil {
			t.Fatal(err)
		}
		si := e.info(sess.Raw)
		if !si.HasScope(auth.ScopeRead) || !si.HasScope(auth.ScopeWrite) || si.Role != "admin" {
			t.Fatalf("session: %+v", si)
		}
		if _, err := e.finishCLI(res.Redirect, c); err == nil {
			t.Fatal("the CLI code is single use")
		}

		// PKCE: a wrong verifier gets nothing
		pd2, c2, err := e.login("", g)
		if err != nil || pd2.Mode != "mfa" {
			t.Fatalf("second login: %+v %v", pd2, err)
		}
		if !pd2.HasTOTP || pd2.HasPasskey {
			t.Fatalf("an authenticator-app account must not be offered a passkey: %+v", pd2)
		}
		in2 := e.info(pd2.Token)
		if _, err := e.svc.VerifyTOTP(ctx, in2, "123456", "203.0.113.9"); !errors.Is(err, auth.ErrLogin) {
			t.Fatal("wrong code")
		}
		if e.count(`SELECT COUNT(*) FROM audit_log WHERE action = 'login_failed'`) != 1 {
			t.Fatal("failed login must be audited")
		}
		code, _ = totp.GenerateCode(secret, time.Now())
		redirect, err := e.svc.VerifyTOTP(ctx, in2, code, "203.0.113.9")
		if err != nil {
			t.Fatal(err)
		}
		bad := c2
		bad.verifier = strings.Repeat("w", 43)
		if _, err := e.finishCLI(redirect, bad); err == nil {
			t.Fatal("wrong PKCE verifier must fail")
		}

		// recovery codes: single use
		pd3, c3, _ := e.login("", g)
		in3 := e.info(pd3.Token)
		redirect, err = e.svc.VerifyRecovery(ctx, in3, strings.ToLower(res.RecoveryCodes[0]), "203.0.113.9")
		if err != nil {
			t.Fatalf("recovery: %v", err)
		}
		if _, err := e.finishCLI(redirect, c3); err != nil {
			t.Fatal(err)
		}
		pd4, _, _ := e.login("", g)
		if _, err := e.svc.VerifyRecovery(ctx, e.info(pd4.Token), res.RecoveryCodes[0], "203.0.113.9"); !errors.Is(err, auth.ErrLogin) {
			t.Fatal("a recovery code works once")
		}
		var hash []byte
		_ = p.DB().QueryRow(`SELECT code_hash FROM recovery_codes LIMIT 1`).Scan(&hash)
		if bytes.Contains(hash, []byte(res.RecoveryCodes[0])) {
			t.Fatal("recovery codes are stored hashed")
		}

		// an account with only an authenticator app confirms with a code, and a code works only once
		sid, err := e.svc.StartStepUp(ctx, si, "reveal", "A")
		if err != nil {
			t.Fatalf("an authenticator-app account can confirm: %v", err)
		}
		if pk, tp, err := e.svc.StepUpMethods(ctx, sid); err != nil || pk || !tp {
			t.Fatalf("methods must be the account's own: passkey=%v totp=%v %v", pk, tp, err)
		}
		if err := e.svc.FinishStepUpTOTP(ctx, sid, code); !errors.Is(err, auth.ErrLogin) {
			t.Fatal("the code that was just used to sign in must not confirm (replay)")
		}
		if err := e.svc.FinishStepUpTOTP(ctx, sid, "000000"); !errors.Is(err, auth.ErrLogin) {
			t.Fatal("a wrong code must not confirm")
		}
		if e.svc.StepUpDone(si, sid) {
			t.Fatal("nothing was confirmed yet")
		}
		e.clock = e.clock.Add(31 * time.Second) // the next 30-second step
		fresh, _ := totp.GenerateCode(secret, e.clock)
		if err := e.svc.FinishStepUpTOTP(ctx, sid, fresh); err != nil {
			t.Fatalf("a fresh code confirms: %v", err)
		}
		if !e.svc.StepUpDone(si, sid) || !e.svc.ConsumeStepUp(si, sid, "reveal", "A") || e.svc.ConsumeStepUp(si, sid, "reveal", "A") {
			t.Fatal("the grant is single use and bound to the request")
		}
		sid2, _ := e.svc.StartStepUp(ctx, si, "run", "A")
		if err := e.svc.FinishStepUpTOTP(ctx, sid2, fresh); !errors.Is(err, auth.ErrLogin) {
			t.Fatal("a code works once, across confirmations too")
		}

		// logout invalidates the session
		if err := e.svc.Logout(ctx, si, "203.0.113.9"); err != nil {
			t.Fatal(err)
		}
		if _, err := e.tokens.Validate(ctx, sess.Raw); !errors.Is(err, auth.ErrInvalid) {
			t.Fatal("logout")
		}

		// disabled identities cannot log in
		admin2 := e.activeAdmin()
		if err := e.ids.Disable(ctx, admin2, "boss@example.test"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := e.login("", g); !errors.Is(err, auth.ErrLogin) {
			t.Fatal("disabled")
		}
		if err := e.log.Verify(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func (e *env) activeAdmin() access.Actor {
	id := uuid.New()
	if _, err := e.p.DB().Exec(e.p.Rebind(`INSERT INTO principals (id, kind, name, email, role, status) VALUES (?, 'human', ?, ?, 'admin', 'active')`), id, id.String(), "a2@example.test"); err != nil {
		e.t.Fatal(err)
	}
	return access.Actor{ID: id}
}

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func TestPasskeyLoginAndStepUp(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		g := auth.Identity{Subject: "sub-1", Email: "pk@example.test", EmailVerified: true}
		pd, c, err := e.login(e.bootstrap("pk@example.test"), g)
		if err != nil {
			t.Fatal(err)
		}
		in := e.info(pd.Token)
		dev := &authtest.Authenticator{RPID: rpID, Origin: origin}

		opts, err := e.svc.BeginPasskeyRegistration(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		if opts.Response.AuthenticatorSelection.UserVerification != "required" {
			t.Fatal("user verification must be required")
		}
		if _, err := e.svc.FinishPasskeyRegistration(ctx, in, dev.Register(t, raw(opts), false), "203.0.113.9"); !errors.Is(err, auth.ErrLogin) {
			t.Fatal("a registration without user verification must fail")
		}
		opts, _ = e.svc.BeginPasskeyRegistration(ctx, in)
		res, err := e.svc.FinishPasskeyRegistration(ctx, in, dev.Register(t, raw(opts), true), "203.0.113.9")
		if err != nil || len(res.RecoveryCodes) != 10 {
			t.Fatalf("register: %v", err)
		}
		if _, err := e.finishCLI(res.Redirect, c); err != nil {
			t.Fatal(err)
		}

		// second factor with the passkey
		pd2, c2, _ := e.login("", g)
		if !pd2.HasPasskey || pd2.HasTOTP {
			t.Fatalf("a passkey account must not be offered an authenticator code: %+v", pd2)
		}
		in2 := e.info(pd2.Token)
		a, err := e.svc.BeginPasskeyLogin(ctx, in2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.FinishPasskeyLogin(ctx, in2, dev.Assert(t, raw(a), false), "203.0.113.9"); !errors.Is(err, auth.ErrLogin) {
			t.Fatal("an assertion without user verification must fail")
		}
		a, _ = e.svc.BeginPasskeyLogin(ctx, in2)
		redirect, err := e.svc.FinishPasskeyLogin(ctx, in2, dev.Assert(t, raw(a), true), "203.0.113.9")
		if err != nil {
			t.Fatal(err)
		}
		sess, err := e.finishCLI(redirect, c2)
		if err != nil {
			t.Fatal(err)
		}
		si := e.info(sess.Raw)

		// step-up: bound to principal, purpose and subject; single use; 60 s
		id, err := e.svc.StartStepUp(ctx, si, "reveal", "STRIPE_KEY env:prod")
		if err != nil {
			t.Fatal(err)
		}
		if e.svc.ConsumeStepUp(si, id, "reveal", "STRIPE_KEY env:prod") {
			t.Fatal("no grant before the assertion")
		}
		a, err = e.svc.BeginStepUp(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.svc.FinishStepUp(ctx, id, dev.Assert(t, raw(a), false)); err == nil {
			t.Fatal("step-up needs user verification")
		}
		a, _ = e.svc.BeginStepUp(ctx, id)
		if err := e.svc.FinishStepUp(ctx, id, dev.Assert(t, raw(a), true)); err != nil {
			t.Fatal(err)
		}
		if !e.svc.StepUpDone(si, id) {
			t.Fatal("poll must see the grant")
		}
		if e.svc.ConsumeStepUp(si, id, "reveal", "OTHER") {
			t.Fatal("grant is bound to its request")
		}
		// start over for the happy path and expiry
		id, _ = e.svc.StartStepUp(ctx, si, "reveal", "A")
		a, _ = e.svc.BeginStepUp(ctx, id)
		_ = e.svc.FinishStepUp(ctx, id, dev.Assert(t, raw(a), true))
		if !e.svc.ConsumeStepUp(si, id, "reveal", "A") {
			t.Fatal("valid grant")
		}
		if e.svc.ConsumeStepUp(si, id, "reveal", "A") {
			t.Fatal("grants are single use")
		}
		id, _ = e.svc.StartStepUp(ctx, si, "run", "A")
		a, _ = e.svc.BeginStepUp(ctx, id)
		_ = e.svc.FinishStepUp(ctx, id, dev.Assert(t, raw(a), true))
		e.clock = e.clock.Add(61 * time.Second)
		if e.svc.ConsumeStepUp(si, id, "run", "A") {
			t.Fatal("grants expire after 60 seconds")
		}

		// machines never get one
		mid := uuid.New()
		if _, err := p.DB().Exec(p.Rebind(`INSERT INTO principals (id, kind, name, owner_id, status) VALUES (?, 'machine', 'ci', ?, 'active')`), mid, si.PrincipalID); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.StartStepUp(ctx, auth.Info{PrincipalID: mid, Machine: true, Scopes: []string{"read"}}, "reveal", "A"); err == nil {
			t.Fatal("machines can never get a step-up")
		}
	})
}
