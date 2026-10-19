package secrets

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/access"
	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/keys"
	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

var ctx = context.Background()

const fakeValue = "sk_test_FAKE_EXAMPLE"

type env struct {
	t   *testing.T
	p   storage.Provider
	svc *Service
	log *audit.Log
}

func setup(t *testing.T, p storage.Provider) *env {
	kf, _ := keys.GenerateMasterKey(1)
	kp, err := keys.ParseMasterKeys(kf)
	if err != nil {
		t.Fatal(err)
	}
	log := audit.New(p)
	return &env{t, p, New(p, kp, log), log}
}

func (e *env) exec(q string, args ...any) {
	e.t.Helper()
	if _, err := e.p.DB().Exec(e.p.Rebind(q), args...); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) human(role string) access.Actor {
	id := uuid.New()
	e.exec(`INSERT INTO principals (id, kind, name, email, role, status) VALUES (?, 'human', ?, ?, ?, 'active')`, id, "h-"+id.String(), "h@example.test", role)
	return access.Actor{ID: id, IP: "203.0.113.1"}
}

func (e *env) machine(owner access.Actor) access.Actor {
	id := uuid.New()
	e.exec(`INSERT INTO principals (id, kind, name, owner_id, status) VALUES (?, 'machine', ?, ?, 'active')`, id, "m-"+id.String(), owner.ID)
	return access.Actor{ID: id, Machine: true, IP: "203.0.113.2"}
}

func (e *env) grant(a access.Actor, perm string, tags ...string) {
	sel, err := storage.NormalizeTags(tags)
	if err != nil {
		e.t.Fatal(err)
	}
	e.exec(`INSERT INTO grants (id, subject_type, subject_id, tag_selector, permission) VALUES (?, 'principal', ?, ?, ?)`,
		uuid.New(), a.ID, e.p.TagsArg(sel), perm)
}

func (e *env) set(a access.Actor, name, value string, tags ...string) SetResult {
	e.t.Helper()
	r, err := e.svc.Set(ctx, a, SetInput{Name: name, Tags: tags, Value: []byte(value), Create: true})
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func code(err error) string {
	var de *Error
	if errors.As(err, &de) {
		return de.Code
	}
	return "other:" + errString(err)
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

func (e *env) auditCount(a access.Actor, action, result string) int {
	e.t.Helper()
	var n int
	if err := e.p.DB().QueryRow(e.p.Rebind(`SELECT COUNT(*) FROM audit_log WHERE principal_id = ? AND action = ? AND result = ?`), a.ID, action, result).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func TestSetVersionsRevealRun(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")

		if _, err := e.svc.Set(ctx, u, SetInput{Name: "stripe_key", Tags: []string{"app:shop"}, Value: []byte(fakeValue)}); code(err) != CodeWouldCreate {
			t.Fatalf("missing secret needs confirmation, got %v", err)
		}
		if r := e.set(u, "stripe_key", fakeValue, "app:shop", "env:prod"); r.Version != 1 || !r.Created || r.Name != "STRIPE_KEY" {
			t.Fatalf("got %+v", r)
		}
		if r := e.set(u, "STRIPE_KEY", fakeValue+"2", "env:prod", "app:shop"); r.Version != 2 || r.Created {
			t.Fatalf("exact match must add a version, got %+v", r)
		}

		list, err := e.svc.List(ctx, u, Selector{Tags: []string{"app:shop"}})
		if err != nil || len(list) != 1 || list[0].Version != 2 {
			t.Fatalf("list: %+v %v", list, err)
		}
		sel := Selector{Name: "STRIPE_KEY", Tags: []string{"env:prod"}}
		if _, err := e.svc.Reveal(ctx, u, sel, false); code(err) != CodeStepUp {
			t.Fatalf("reveal without step-up: %v", err)
		}
		v, err := e.svc.Reveal(ctx, u, sel, true)
		if err != nil || string(v.Data) != fakeValue+"2" || v.Version != 2 {
			t.Fatalf("reveal: %v", err)
		}
		vals, err := e.svc.Run(ctx, u, Selector{Tags: []string{"app:shop"}}, false)
		if err != nil || len(vals) != 1 || string(vals[0].Data) != fakeValue+"2" {
			t.Fatalf("run: %v", err)
		}
		if e.auditCount(u, "reveal", "ok") != 1 || e.auditCount(u, "read", "ok") != 1 || e.auditCount(u, "create", "ok") != 2 {
			t.Fatal("expected one audit row per create/reveal/read")
		}
		if err := e.log.Verify(ctx); err != nil {
			t.Fatal(err)
		}
		assertNoValueInAudit(t, e, fakeValue)
	})
}

func assertNoValueInAudit(t *testing.T, e *env, v string) {
	t.Helper()
	rows, err := e.log.List(ctx, audit.Filter{}, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if strings.Contains(r.Action+r.Result+r.TargetType+toString(r.Metadata), v) {
			t.Fatal("a value leaked into the audit log")
		}
	}
}

func toString(m map[string]any) string {
	var b strings.Builder
	for k, v := range m {
		b.WriteString(k)
		b.WriteString(strings.TrimSpace(strings.Join([]string{toS(v)}, "")))
	}
	return b.String()
}

func toS(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func TestDenyByDefaultAndAudited(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		owner := e.human("member")
		e.grant(owner, "write", "app:shop")
		e.set(owner, "DB_URL", fakeValue, "app:shop")

		nobody := e.human("admin") // admin role grants no secret access
		if _, err := e.svc.Set(ctx, nobody, SetInput{Name: "X", Tags: []string{"app:shop"}, Value: []byte("v"), Create: true}); code(err) != CodeDenied {
			t.Fatalf("set without grant: %v", err)
		}
		if e.auditCount(nobody, "create", "denied") != 1 {
			t.Fatal("denial must be audited")
		}
		if l, err := e.svc.List(ctx, nobody, Selector{}); err != nil || len(l) != 0 {
			t.Fatalf("list must hide secrets: %v %v", l, err)
		}
		if _, err := e.svc.Run(ctx, nobody, Selector{Name: "DB_URL", Tags: []string{"app:shop"}}, false); code(err) != CodeDenied {
			t.Fatalf("run of a named unreadable secret: %v", err)
		}
		if e.auditCount(nobody, "read", "denied") != 1 {
			t.Fatal("read denial must be audited")
		}
		if _, err := e.svc.Reveal(ctx, nobody, Selector{Name: "NOPE", Tags: []string{"app:shop"}}, true); code(err) != CodeNotFound {
			t.Fatalf("unknown secret: %v", err)
		}
		// read-only grant cannot write
		reader := e.human("member")
		e.grant(reader, "read", "app:shop")
		if _, err := e.svc.Revoke(ctx, reader, Selector{Name: "DB_URL"}); code(err) != CodeDenied {
			t.Fatalf("revoke with read grant: %v", err)
		}
	})
}

func TestRevokeBlocksUntilNextSet(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")
		e.set(u, "STRIPE_KEY", "old-FAKE", "app:shop", "env:prod")
		e.set(u, "STRIPE_KEY", "new-FAKE", "app:shop", "env:prod")

		if _, err := e.svc.Revoke(ctx, u, Selector{Name: "STRIPE_KEY", Tags: []string{"env:prod"}}); err != nil {
			t.Fatal(err)
		}
		if e.auditCount(u, "mark_compromised", "ok") != 1 {
			t.Fatal("revoke must be audited")
		}
		sel := Selector{Name: "STRIPE_KEY", Tags: []string{"env:prod"}}
		if _, err := e.svc.Reveal(ctx, u, sel, true); code(err) != CodeBlocked {
			t.Fatalf("reveal after revoke: %v", err)
		}
		_, err := e.svc.Run(ctx, u, Selector{Tags: []string{"app:shop"}}, false)
		var de *Error
		if !errors.As(err, &de) || de.Code != CodeBlocked || !strings.Contains(strings.Join(de.Items, ","), "STRIPE_KEY") {
			t.Fatalf("run after revoke must name the secret: %v", err)
		}
		e.set(u, "STRIPE_KEY", "third-FAKE", "app:shop", "env:prod")
		v, err := e.svc.Reveal(ctx, u, sel, true)
		if err != nil || string(v.Data) != "third-FAKE" || v.Version != 3 {
			t.Fatalf("after a new set the secret works again: %v", err)
		}
	})
}

func TestClashAndBulkAllOrNothing(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")
		e.set(u, "STRIPE_KEY", "v", "app:shop", "env:prod", "team:pay")
		e.set(u, "STRIPE_KEY", "v", "app:shop", "env:qa", "team:pay")
		e.set(u, "PAY_TOKEN", "v", "app:shop", "env:prod", "team:pay")

		_, err := e.svc.Update(ctx, u, Selector{Tags: []string{"team:pay"}}, Change{AddTags: []string{"env:qa"}}, false)
		var de *Error
		if !errors.As(err, &de) || de.Code != CodeClash || len(de.Items) == 0 {
			t.Fatalf("expected a clash, got %v", err)
		}
		if got, _ := e.svc.List(ctx, u, Selector{Tags: []string{"env:qa"}}); len(got) != 1 {
			t.Fatalf("nothing may change after a clash, env:qa has %d", len(got))
		}
		// no clash: applies to all selected
		n, err := e.svc.Update(ctx, u, Selector{Name: "PAY_TOKEN"}, Change{AddTags: []string{"region:eu"}}, false)
		if err != nil || len(n) != 1 {
			t.Fatalf("update: %v", err)
		}
		// rename needs exactly one
		if _, err := e.svc.Update(ctx, u, Selector{Tags: []string{"team:pay"}}, Change{Rename: "X"}, false); code(err) != CodeNeedsOne {
			t.Fatalf("rename of several: %v", err)
		}
		if _, err := e.svc.Update(ctx, u, Selector{Name: "PAY_TOKEN"}, Change{Rename: "STRIPE_KEY", RemoveTags: []string{"region:eu"}}, false); code(err) != CodeClash {
			t.Fatalf("rename onto an existing identity: %v", err)
		}
		if _, err := e.svc.Update(ctx, u, Selector{Name: "PAY_TOKEN"}, Change{Rename: "PAY_KEY"}, false); err != nil {
			t.Fatal(err)
		}
		// moving a secret out of the actor's grant is denied
		if _, err := e.svc.Update(ctx, u, Selector{Name: "PAY_KEY"}, Change{RemoveTags: []string{"app:shop"}}, false); code(err) != CodeDenied {
			t.Fatalf("moving out of the grant: %v", err)
		}
		if err := e.log.Verify(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAmbiguousName(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")
		e.set(u, "BASE_URL", "a", "app:shop", "env:dev")
		e.set(u, "BASE_URL", "b", "app:shop", "env:prod")
		_, err := e.svc.Run(ctx, u, Selector{Tags: []string{"app:shop"}}, false)
		var de *Error
		if !errors.As(err, &de) || de.Code != CodeAmbiguous || len(de.Items) != 2 {
			t.Fatalf("got %v", err)
		}
		if _, err := e.svc.Reveal(ctx, u, Selector{Name: "BASE_URL"}, true); code(err) != CodeAmbiguous {
			t.Fatalf("reveal: %v", err)
		}
		if vals, err := e.svc.Run(ctx, u, Selector{Tags: []string{"app:shop", "env:dev"}}, false); err != nil || len(vals) != 1 {
			t.Fatalf("adding a tag resolves it: %v", err)
		}
	})
}

func TestAuthorizeAndMachines(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")
		e.set(u, "STRIPE_KEY", fakeValue, "app:shop", "env:prod")
		e.set(u, "LOG_LEVEL", "debug", "app:shop", "env:dev")

		on, off := true, false
		sel := Selector{Name: "STRIPE_KEY"}
		if _, err := e.svc.Update(ctx, u, sel, Change{Authorize: &on}, false); err != nil {
			t.Fatalf("authorize on needs no step-up: %v", err)
		}
		if _, err := e.svc.Run(ctx, u, Selector{Tags: []string{"app:shop"}}, false); code(err) != CodeStepUp {
			t.Fatalf("run with a requires_authorize secret: %v", err)
		}
		if vals, err := e.svc.Run(ctx, u, Selector{Tags: []string{"app:shop"}}, true); err != nil || len(vals) != 2 {
			t.Fatalf("run with step-up: %v", err)
		}
		if _, err := e.svc.Update(ctx, u, sel, Change{Authorize: &off}, false); code(err) != CodeStepUp {
			t.Fatalf("authorize off needs step-up: %v", err)
		}

		m := e.machine(u)
		e.grant(m, "read", "app:shop")
		if _, err := e.svc.Reveal(ctx, m, Selector{Name: "LOG_LEVEL"}, true); code(err) != CodeDenied {
			t.Fatalf("machines never reveal: %v", err)
		}
		if _, err := e.svc.Run(ctx, m, Selector{Tags: []string{"env:dev"}}, false); err != nil {
			t.Fatalf("machine run of a plain secret: %v", err)
		}
		if _, err := e.svc.Run(ctx, m, Selector{Name: "STRIPE_KEY"}, true); code(err) != CodeDenied {
			t.Fatalf("machines cannot run requires_authorize secrets: %v", err)
		}
		// a machine never exceeds its owner: grant it more than the owner has
		m2 := e.machine(u)
		e.grant(m2, "read", "app:billing")
		other := e.human("member")
		e.grant(other, "write", "app:billing")
		e.set(other, "BILL", "v", "app:billing")
		if _, err := e.svc.Run(ctx, m2, Selector{Name: "BILL"}, false); code(err) != CodeDenied {
			t.Fatalf("machine beyond its owner: %v", err)
		}
	})
}

func TestArchiveHidesAndFreesIdentity(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")
		e.set(u, "OLD", "v", "app:shop")
		if _, err := e.svc.Archive(ctx, u, Selector{Name: "OLD"}); err != nil {
			t.Fatal(err)
		}
		if l, _ := e.svc.List(ctx, u, Selector{}); len(l) != 0 {
			t.Fatal("archived secrets are hidden")
		}
		if _, err := e.svc.Run(ctx, u, Selector{Name: "OLD"}, false); code(err) != CodeNotFound {
			t.Fatalf("archived secrets are not served: %v", err)
		}
		if r := e.set(u, "OLD", "v", "app:shop"); r.Version != 1 || !r.Created {
			t.Fatalf("name+tags can be reused: %+v", r)
		}
		var n int
		if err := p.DB().QueryRow(`SELECT COUNT(*) FROM secret_versions`).Scan(&n); err != nil || n != 2 {
			t.Fatalf("history is kept: %d %v", n, err)
		}
	})
}

func TestLimitsAndValidation(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")
		set := func(in SetInput) error {
			in.Create = true
			in.Tags = []string{"app:shop"}
			_, err := e.svc.Set(ctx, u, in)
			return err
		}
		if code(set(SetInput{Name: "BIG", Value: make([]byte, MaxText+1)})) != CodeInvalid {
			t.Fatal("text over 64 KB")
		}
		if err := set(SetInput{Name: "BIG", Value: make([]byte, MaxText)}); err != nil {
			t.Fatal(err)
		}
		if code(set(SetInput{Name: "F", Kind: "file", Filename: "a.pem", Value: make([]byte, MaxFile+1)})) != CodeInvalid {
			t.Fatal("file over 1 MB")
		}
		if err := set(SetInput{Name: "F", Kind: "file", Filename: "../../a.pem", Value: []byte("x")}); err != nil {
			t.Fatal(err)
		}
		v, err := e.svc.Reveal(ctx, u, Selector{Name: "F"}, true)
		if err != nil || v.Filename != "a.pem" {
			t.Fatalf("file name must be reduced to its base: %q %v", v.Filename, err)
		}
		if code(set(SetInput{Name: "bad name", Value: []byte("x")})) != CodeInvalid {
			t.Fatal("bad name")
		}
		if code(set(SetInput{Name: "E"})) != CodeInvalid {
			t.Fatal("empty value")
		}
		if err := set(SetInput{Name: "GEN", Generate: true}); err != nil {
			t.Fatal(err)
		}
		if g, err := e.svc.Reveal(ctx, u, Selector{Name: "GEN"}, true); err != nil || len(g.Data) != 43 {
			t.Fatal("generated value")
		}
	})
}

func TestKeyRotationRewrapsWithoutTouchingCiphertext(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")

		kf1, _ := keys.GenerateMasterKey(1)
		kp1, _ := keys.ParseMasterKeys(kf1)
		k2, _ := keys.GenerateMasterKey(2)
		ring, err := keys.ParseMasterKeys(append(append([]byte{}, kf1...), k2...))
		if err != nil {
			t.Fatal(err)
		}
		svc1, svc2 := New(p, kp1, e.log), New(p, ring, e.log)
		if _, err := svc1.Set(ctx, u, SetInput{Name: "ROT", Tags: []string{"app:shop"}, Value: []byte(fakeValue), Create: true}); err != nil {
			t.Fatal(err)
		}
		var before []byte
		if err := p.DB().QueryRow(`SELECT ciphertext FROM secret_versions`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if v, err := svc2.Reveal(ctx, u, Selector{Name: "ROT"}, true); err != nil || string(v.Data) != fakeValue {
			t.Fatalf("data stays readable with the extended ring: %v", err)
		}
		if n, err := svc2.RewrapAll(ctx); err != nil || n != 1 {
			t.Fatalf("rewrapped %d: %v", n, err)
		}
		var keyID string
		var after []byte
		if err := p.DB().QueryRow(`SELECT key_id, ciphertext FROM secret_versions`).Scan(&keyID, &after); err != nil {
			t.Fatal(err)
		}
		if keyID != "manual:v2" || !bytes.Equal(before, after) {
			t.Fatalf("key_id %s, ciphertext changed: %v", keyID, !bytes.Equal(before, after))
		}
		if v, err := svc2.Reveal(ctx, u, Selector{Name: "ROT"}, true); err != nil || string(v.Data) != fakeValue {
			t.Fatalf("readable after rewrap: %v", err)
		}
		if n, _ := svc2.RewrapAll(ctx); n != 0 {
			t.Fatal("nothing left to rewrap")
		}
	})
}
