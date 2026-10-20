package auth_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/auth"
	"github.com/victorlunam/kuukura/internal/auth/authtest"
	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func TestPasskeyLoginAndStepUp(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
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
		if !pd2.Passkey || pd2.TOTP {
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
		id, _, err := e.svc.StartStepUp(ctx, si, "reveal", "STRIPE_KEY env:prod")
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
		if err := e.svc.FinishStepUp(ctx, id, dev.Assert(t, raw(a), false), "203.0.113.9"); err == nil {
			t.Fatal("step-up needs user verification")
		}
		if e.count(`SELECT COUNT(*) FROM audit_log WHERE action = 'login_failed' AND result = 'denied'`) != 2 {
			t.Fatal("a failed confirmation must be audited like a failed sign-in (1 sign-in + 1 confirmation)")
		}
		a, _ = e.svc.BeginStepUp(ctx, id)
		if err := e.svc.FinishStepUp(ctx, id, dev.Assert(t, raw(a), true), "203.0.113.9"); err != nil {
			t.Fatal(err)
		}
		if !e.svc.StepUpDone(si, id) {
			t.Fatal("poll must see the grant")
		}
		// someone else's session can neither poll nor spend it
		other := auth.Info{PrincipalID: uuid.New(), Scopes: []string{auth.ScopeRead, auth.ScopeWrite}}
		if e.svc.StepUpDone(other, id) || e.svc.ConsumeStepUp(other, id, "reveal", "STRIPE_KEY env:prod") {
			t.Fatal("another principal cannot see or spend my confirmation")
		}
		if e.svc.ConsumeStepUp(si, id, "reveal", "OTHER") {
			t.Fatal("grant is bound to its request")
		}
		// start over for the happy path and expiry
		id, _, _ = e.svc.StartStepUp(ctx, si, "reveal", "A")
		a, _ = e.svc.BeginStepUp(ctx, id)
		_ = e.svc.FinishStepUp(ctx, id, dev.Assert(t, raw(a), true), "203.0.113.9")
		if !e.svc.ConsumeStepUp(si, id, "reveal", "A") {
			t.Fatal("valid grant")
		}
		if e.svc.ConsumeStepUp(si, id, "reveal", "A") {
			t.Fatal("grants are single use")
		}
		id, _, _ = e.svc.StartStepUp(ctx, si, "run", "A")
		a, _ = e.svc.BeginStepUp(ctx, id)
		_ = e.svc.FinishStepUp(ctx, id, dev.Assert(t, raw(a), true), "203.0.113.9")
		e.clock = e.clock.Add(61 * time.Second)
		if e.svc.ConsumeStepUp(si, id, "run", "A") {
			t.Fatal("grants expire after 60 seconds")
		}

		// a passkey whose sign count goes back may have been copied: the sign-in works but the audit trail says so
		dev.Rewind()
		id, _, _ = e.svc.StartStepUp(ctx, si, "run", "A")
		a, _ = e.svc.BeginStepUp(ctx, id)
		if err := e.svc.FinishStepUp(ctx, id, dev.Assert(t, raw(a), true), "203.0.113.9"); err != nil {
			t.Fatal(err)
		}
		if e.count(`SELECT COUNT(*) FROM audit_log WHERE action = 'update' AND target_type = 'principal'`) != 1 {
			t.Fatal("a sign count that did not advance must be audited")
		}

		// machines never get one
		mid := storagetest.Machine(t, p, si.PrincipalID, "ci")
		if _, _, err := e.svc.StartStepUp(ctx, auth.Info{PrincipalID: mid, Machine: true, Scopes: []string{"read"}}, "reveal", "A"); err == nil {
			t.Fatal("machines can never get a step-up")
		}
	})
}
