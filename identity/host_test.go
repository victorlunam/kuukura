package identity

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/victorlunam/kuukura/access"
	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/auth"
	"github.com/victorlunam/kuukura/keys"
	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
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

func TestHostPrincipal(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		a, err := e.svc.HostPrincipal(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if b, err := e.svc.HostPrincipal(ctx); err != nil || a != b {
			t.Fatalf("the host principal is created once: %v", err)
		}
		if e.count(`SELECT COUNT(*) FROM principals WHERE id = ? AND kind = 'machine' AND name = 'ku-server' AND status = 'disabled' AND owner_id IS NULL AND role IS NULL`, a) != 1 {
			t.Fatal("a disabled machine without owner")
		}
		people, err := e.svc.ListPeople(ctx)
		if err != nil || len(people) != 0 {
			t.Fatalf("the host principal is hidden: %v %v", people, err)
		}
		admin := e.person("admin", "active")
		if _, err := e.svc.InviteMachine(ctx, admin, HostName); code(err) != access.CodeInvalid {
			t.Fatalf("the name is reserved: %v", err)
		}
		if err := e.svc.DisableByHost(ctx, HostName); code(err) != access.CodeNotFound {
			t.Fatalf("the host principal is not an identity to manage: %v", err)
		}
		if _, err := e.svc.EnableByHost(ctx, HostName); code(err) != access.CodeNotFound {
			t.Fatalf("the host principal cannot be enabled: %v", err)
		}
	})
}

func TestInviteByHost(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		host, _ := e.svc.HostPrincipal(ctx)
		inv, err := e.svc.InviteByHost(ctx, "Dev@Example.test", false)
		if err != nil || time.Until(inv.ExpiresAt) > 15*time.Minute {
			t.Fatalf("%+v %v", inv, err)
		}
		if e.count(`SELECT COUNT(*) FROM principals WHERE name = 'dev@example.test' AND role = 'member' AND status = 'invited'`) != 1 {
			t.Fatal("a member by default")
		}
		if _, err := e.svc.InviteByHost(ctx, "dev@example.test", false); err != nil {
			t.Fatalf("a fresh link for someone who has not signed in: %v", err)
		}
		if _, err := e.svc.InviteByHost(ctx, "dev@example.test", true); code(err) != access.CodeConflict {
			t.Fatalf("the role must match: %v", err)
		}
		active := e.person("member", "active")
		if _, err := e.svc.InviteByHost(ctx, e.name(active), false); code(err) != access.CodeConflict {
			t.Fatalf("an enrolled person needs reset-factors: %v", err)
		}
		rows, _ := e.log.List(ctx, audit.Filter{}, 10)
		if len(rows) != 2 {
			t.Fatalf("two invites: %d", len(rows))
		}
		for _, r := range rows {
			if r.Principal != host || r.Action != "invite" {
				t.Fatalf("audited under the host principal: %+v", r)
			}
			for _, v := range r.Metadata {
				if s, _ := v.(string); strings.Contains(s, "ku_") {
					t.Fatal("link in audit")
				}
			}
		}
	})
}

func TestListDisableEnableByHost(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		admin := e.person("admin", "active")
		user := e.person("member", "active")
		if _, err := p.DB().Exec(p.Rebind(`INSERT INTO credentials (id, principal_id, kind, public_key) VALUES (?, ?, 'passkey', ?)`), uuid.New(), user.ID, []byte{1}); err != nil {
			t.Fatal(err)
		}
		mid := uuid.New()
		if _, err := p.DB().Exec(p.Rebind(`INSERT INTO principals (id, kind, name, owner_id, status) VALUES (?, 'machine', 'ci', ?, 'active')`), mid, user.ID); err != nil {
			t.Fatal(err)
		}
		people, err := e.svc.ListPeople(ctx)
		if err != nil || len(people) != 3 {
			t.Fatalf("%v %v", people, err)
		}
		for _, pe := range people {
			if pe.Name == e.name(user) && (pe.Factors != 1 || pe.Role != "member" || pe.Status != "active" || pe.Created.IsZero()) {
				t.Fatalf("%+v", pe)
			}
		}
		if err := e.svc.DisableByHost(ctx, e.name(admin)); code(err) != access.CodeLastAdmin {
			t.Fatalf("the last admin stays: %v", err)
		}
		if err := e.svc.DisableByHost(ctx, e.name(user)); err != nil {
			t.Fatal(err)
		}
		if e.count(`SELECT COUNT(*) FROM principals WHERE id IN (?, ?) AND status = 'disabled'`, user.ID, mid) != 2 {
			t.Fatal("the person and the machine are disabled")
		}
		if _, err := e.svc.EnableByHost(ctx, "ci"); code(err) != access.CodeConflict {
			t.Fatalf("a machine needs its owner enabled first: %v", err)
		}
		if st, err := e.svc.EnableByHost(ctx, e.name(user)); err != nil || st != "active" {
			t.Fatalf("%q %v", st, err)
		}
		if st, err := e.svc.EnableByHost(ctx, "ci"); err != nil || st != "active" {
			t.Fatalf("%q %v", st, err)
		}
		if _, err := e.svc.EnableByHost(ctx, "ci"); code(err) != access.CodeConflict {
			t.Fatalf("not disabled: %v", err)
		}
		if _, err := e.svc.EnableByHost(ctx, "nobody"); code(err) != access.CodeNotFound {
			t.Fatalf("%v", err)
		}
		host, _ := e.svc.HostPrincipal(ctx)
		if e.count(`SELECT COUNT(*) FROM audit_log WHERE principal_id = ? AND action IN ('disable', 'update')`, host) != 3 {
			t.Fatal("every change is audited under the host principal")
		}
		if err := e.log.Verify(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

// Enable is the admin's side of EnableByHost: same rules, audited under the admin, and members cannot use it.
func TestEnableByAdmin(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		admin := e.person("admin", "active")
		user := e.person("member", "active")
		if _, err := e.svc.Enable(ctx, user, e.name(user)); code(err) != access.CodeDenied {
			t.Fatalf("members cannot enable: %v", err)
		}
		if _, err := e.svc.Enable(ctx, admin, e.name(user)); code(err) != access.CodeConflict {
			t.Fatalf("not disabled: %v", err)
		}
		if err := e.svc.Disable(ctx, admin, e.name(user)); err != nil {
			t.Fatal(err)
		}
		// a person without a factor goes back to enrolling, not to active
		if st, err := e.svc.Enable(ctx, admin, e.name(user)); err != nil || st != "invited" {
			t.Fatalf("%q %v", st, err)
		}
		if e.count(`SELECT COUNT(*) FROM audit_log WHERE principal_id = ? AND action = 'update'`, admin.ID) != 1 {
			t.Fatal("the enable is audited under the admin")
		}
		if err := e.log.Verify(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

// A person who lost their passkey and recovery codes: reset-factors, then sign in through the link, enroll a new
// factor, and log in; nothing from before works.
func TestResetFactorsByHost(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		clock := time.Now().UTC()
		e.tokens.Now = func() time.Time { return clock }
		kf, _ := keys.GenerateMasterKey(1)
		kp, _ := keys.ParseMasterKeys(kf)
		idp := &fakeIDP{map[string]auth.Identity{}}
		as, err := auth.NewService(p, e.log, e.tokens, idp, kp, auth.Config{RPID: "vault.example.test", RPOrigin: "https://vault.example.test", Issuer: "kuukura"})
		if err != nil {
			t.Fatal(err)
		}
		google := auth.Identity{Subject: "sub-dev", Email: "dev@example.test", EmailVerified: true}
		signIn := func(invite string) auth.Pending {
			t.Helper()
			cli := auth.CLIParams{}
			if invite == "" { // a plain sign-in needs the CLI's parameters
				cli = auth.CLIParams{Port: 53682, Challenge: strings.Repeat("c", 43), State: "st"}
			}
			u, err := as.StartLogin(invite, cli)
			if err != nil {
				t.Fatal(err)
			}
			state, _ := url.Parse(u)
			code := uuid.NewString()
			idp.byCode[code] = google
			pd, err := as.Callback(ctx, state.Query().Get("state"), code, "203.0.113.9")
			if err != nil {
				t.Fatal(err)
			}
			return pd
		}
		enroll := func(pd auth.Pending) (secret string, codes []string) {
			t.Helper()
			in, err := e.tokens.Validate(ctx, pd.Token)
			if err != nil || pd.Mode != "enroll" {
				t.Fatalf("%+v %v", pd, err)
			}
			secret, _, err = as.BeginTOTP(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			code, _ := totp.GenerateCode(secret, clock)
			res, err := as.ConfirmTOTP(ctx, in, code, "203.0.113.9")
			if err != nil {
				t.Fatal(err)
			}
			return secret, res.RecoveryCodes
		}

		inv, err := e.svc.InviteByHost(ctx, "dev@example.test", false)
		if err != nil {
			t.Fatal(err)
		}
		oldSecret, oldCodes := enroll(signIn(inv.Token))
		if len(oldCodes) != 10 {
			t.Fatal("recovery codes on first enrollment")
		}

		// the start-up key check covers authenticator secrets too
		if has, err := as.HasTOTP(ctx); err != nil || !has {
			t.Fatalf("%v %v", has, err)
		}
		if err := as.CheckKey(ctx); err != nil {
			t.Fatalf("the right key passes: %v", err)
		}
		otherKF, _ := keys.GenerateMasterKey(1)
		otherKP, _ := keys.ParseMasterKeys(otherKF)
		as2, err := auth.NewService(p, e.log, e.tokens, idp, otherKP, auth.Config{RPID: "vault.example.test", RPOrigin: "https://vault.example.test", Issuer: "kuukura"})
		if err != nil {
			t.Fatal(err)
		}
		if err := as2.CheckKey(ctx); err == nil || err.Error() != "the master key does not match the data (key manual:v1 cannot open it)" {
			t.Fatalf("a wrong key is found at start: %v", err)
		}

		dev := access.Actor{}
		if err := p.DB().QueryRow(p.Rebind(`SELECT id FROM principals WHERE name = 'dev@example.test'`)).Scan(&dev.ID); err != nil {
			t.Fatal(err)
		}
		session, err := e.issue(dev.ID, auth.KindSession, []string{"read"})
		if err != nil {
			t.Fatal(err)
		}

		if _, err := e.svc.ResetFactorsByHost(ctx, "nobody@example.test"); code(err) != access.CodeNotFound {
			t.Fatalf("%v", err)
		}
		link, err := e.svc.ResetFactorsByHost(ctx, "dev@example.test")
		if err != nil || link.ExpiresAt.Sub(clock) > 15*time.Minute {
			t.Fatalf("a 15 minute link: %+v %v", link, err)
		}
		if e.count(`SELECT COUNT(*) FROM credentials WHERE principal_id = ?`, dev.ID) != 0 || e.count(`SELECT COUNT(*) FROM recovery_codes WHERE principal_id = ?`, dev.ID) != 0 {
			t.Fatal("factors and recovery codes are gone")
		}
		if _, err := e.tokens.Validate(ctx, session); !errors.Is(err, auth.ErrInvalid) {
			t.Fatal("sessions end")
		}
		if e.count(`SELECT COUNT(*) FROM principals WHERE id = ? AND status = 'invited'`, dev.ID) != 1 {
			t.Fatal("back in enrollment")
		}
		if _, err := e.svc.ResetFactorsByHost(ctx, "dev@example.test"); code(err) != access.CodeConflict {
			t.Fatalf("a person in enrollment has nothing to reset: %v", err)
		}

		// the link leads through sign-in to enrollment, once
		newSecret, newCodes := enroll(signIn(link.Token))
		if newSecret == oldSecret || newCodes[0] == oldCodes[0] {
			t.Fatal("new factor, new recovery codes")
		}
		host, _ := e.svc.HostPrincipal(ctx)
		if e.count(`SELECT COUNT(*) FROM audit_log WHERE principal_id = ? AND action = 'update'`, host) != 1 {
			t.Fatal("the reset is audited under the host principal")
		}

		// log in again: only the new factor works
		mfa := signIn("")
		if mfa.Mode != "mfa" || !mfa.TOTP {
			t.Fatalf("%+v", mfa)
		}
		in, err := e.tokens.Validate(ctx, mfa.Token)
		if err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(31 * time.Second)
		oldCode, _ := totp.GenerateCode(oldSecret, clock)
		if _, err := as.VerifyTOTP(ctx, in, oldCode, "203.0.113.9"); !errors.Is(err, auth.ErrLogin) {
			t.Fatal("the old authenticator no longer works")
		}
		if _, err := as.VerifyRecovery(ctx, in, oldCodes[0], "203.0.113.9"); !errors.Is(err, auth.ErrLogin) {
			t.Fatal("the old recovery codes no longer work")
		}
		newCode, _ := totp.GenerateCode(newSecret, clock)
		if _, err := as.VerifyTOTP(ctx, in, newCode, "203.0.113.9"); err != nil {
			t.Fatalf("the new factor works: %v", err)
		}
	})
}
