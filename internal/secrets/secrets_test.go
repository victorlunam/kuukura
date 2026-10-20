package secrets

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/access"
	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/keys"
	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

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
	r, err := e.svc.Set(e.t.Context(), a, SetInput{Name: name, Tags: tags, Value: []byte(value), Create: true})
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
	if err == nil {
		return "<nil>"
	}
	return "other:" + err.Error()
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
		ctx := t.Context()
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")

		if _, err := e.svc.Set(ctx, u, SetInput{Name: "stripe_key", Tags: []string{"app:shop"}, Value: []byte(fakeValue)}); code(err) != access.CodeWouldCreate {
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
		if _, err := e.svc.Reveal(ctx, u, sel, false); code(err) != access.CodeStepUp {
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
		for _, v := range []string{fakeValue, fakeValue + "2"} {
			if e.auditHolds(v) {
				t.Fatalf("the value %q leaked into the audit log", v)
			}
		}
	})
}

// auditHolds reports whether v appears in any column of any audit row, as stored: every column cast to text, the
// metadata included, and the raw bytes of the hashes.
func (e *env) auditHolds(v string) bool {
	e.t.Helper()
	rows, err := e.p.DB().Query(`SELECT CAST(id AS TEXT), CAST(at AS TEXT), CAST(principal_id AS TEXT), action, CAST(secret_id AS TEXT),
		CAST(version AS TEXT), result, CAST(ip AS TEXT), target_type, CAST(target_id AS TEXT), CAST(metadata AS TEXT), prev_hash, hash FROM audit_log`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	n := 0
	for rows.Next() {
		n++
		fields := make([]any, len(cols))
		for i := range fields {
			fields[i] = new([]byte)
		}
		if err := rows.Scan(fields...); err != nil {
			e.t.Fatal(err)
		}
		for _, f := range fields {
			if bytes.Contains(*f.(*[]byte), []byte(v)) {
				return true
			}
		}
	}
	if err := rows.Err(); err != nil {
		e.t.Fatal(err)
	}
	if n == 0 {
		e.t.Fatal("the audit log is empty: the scan would prove nothing")
	}
	return false
}

// The leak scan must be able to see a value where it is stored, or "not found" means nothing.
func TestAuditScanSeesAPlantedValue(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		e := setup(t, p)
		u := e.human("member")
		if err := e.log.Record(t.Context(), audit.Entry{Principal: u.ID, Action: "list", Metadata: map[string]any{"note": "x" + fakeValue}}); err != nil {
			t.Fatal(err)
		}
		if !e.auditHolds(fakeValue) {
			t.Fatal("a value in the metadata must be found")
		}
		if e.auditHolds("not-there-FAKE") {
			t.Fatal("an absent value must not be found")
		}
	})
}

func TestDenyByDefaultAndAudited(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		owner := e.human("member")
		e.grant(owner, "write", "app:shop")
		e.set(owner, "DB_URL", fakeValue, "app:shop")

		nobody := e.human("admin") // admin role grants no secret access
		if _, err := e.svc.Set(ctx, nobody, SetInput{Name: "X", Tags: []string{"app:shop"}, Value: []byte("v"), Create: true}); code(err) != access.CodeDenied {
			t.Fatalf("set without grant: %v", err)
		}
		if e.auditCount(nobody, "create", "denied") != 1 {
			t.Fatal("denial must be audited")
		}
		if l, err := e.svc.List(ctx, nobody, Selector{}); err != nil || len(l) != 0 {
			t.Fatalf("list must hide secrets: %v %v", l, err)
		}
		// an unreadable secret looks exactly like one that does not exist: same code, same text, nothing about its tags
		_, err := e.svc.Run(ctx, nobody, Selector{Name: "DB_URL", Tags: []string{"app:shop"}}, false)
		_, errMissing := e.svc.Run(ctx, nobody, Selector{Name: "NO_SUCH", Tags: []string{"app:shop"}}, false)
		var de, dm *Error
		if !errors.As(err, &de) || !errors.As(errMissing, &dm) || de.Code != access.CodeNotFound || de.Msg != dm.Msg || len(de.Items) != 0 {
			t.Fatalf("an existing unreadable name must look like a missing one: %v / %v", err, errMissing)
		}
		if e.auditCount(nobody, "read", "denied") != 1 {
			t.Fatal("read denial must be audited")
		}
		if _, err := e.svc.Reveal(ctx, nobody, Selector{Name: "NOPE", Tags: []string{"app:shop"}}, true); code(err) != access.CodeNotFound {
			t.Fatalf("unknown secret: %v", err)
		}
		// read-only grant cannot write
		reader := e.human("member")
		e.grant(reader, "read", "app:shop")
		if _, err := e.svc.Revoke(ctx, reader, Selector{Name: "DB_URL"}); code(err) != access.CodeDenied {
			t.Fatalf("revoke with read grant: %v", err)
		}
	})
}

func TestRevokeBlocksUntilNextSet(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
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
		if _, err := e.svc.Reveal(ctx, u, sel, true); code(err) != access.CodeBlocked {
			t.Fatalf("reveal after revoke: %v", err)
		}
		_, err := e.svc.Run(ctx, u, Selector{Tags: []string{"app:shop"}}, false)
		var de *Error
		if !errors.As(err, &de) || de.Code != access.CodeBlocked || !strings.Contains(strings.Join(de.Items, ","), "STRIPE_KEY") {
			t.Fatalf("run after revoke must name the secret: %v", err)
		}
		// revoking what is already blocked changes and audits nothing
		if names, err := e.svc.Revoke(ctx, u, sel); err != nil || len(names) != 0 || e.auditCount(u, "mark_compromised", "ok") != 1 {
			t.Fatalf("second revoke: %v %v", names, err)
		}
		e.set(u, "STRIPE_KEY", "third-FAKE", "app:shop", "env:prod")
		v, err := e.svc.Reveal(ctx, u, sel, true)
		if err != nil || string(v.Data) != "third-FAKE" || v.Version != 3 {
			t.Fatalf("after a new set the secret works again: %v", err)
		}
	})
}

func TestKindMismatch(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")
		e.set(u, "CERT", "text-FAKE", "app:shop")
		_, err := e.svc.Set(ctx, u, SetInput{Name: "CERT", Tags: []string{"app:shop"}, Kind: "file", Filename: "a.pem", Value: []byte("file-FAKE"), Create: true})
		if code(err) != access.CodeKindMismatch {
			t.Fatalf("a file over a text secret: %v", err)
		}
		var n int
		if err := p.DB().QueryRow(`SELECT COUNT(*) FROM secret_versions`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("a refused kind must add no version: %d %v", n, err)
		}
	})
}

func TestClashAndBulkAllOrNothing(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")
		e.set(u, "STRIPE_KEY", "v", "app:shop", "env:prod", "team:pay")
		e.set(u, "STRIPE_KEY", "v", "app:shop", "env:qa", "team:pay")
		e.set(u, "PAY_TOKEN", "v", "app:shop", "env:prod", "team:pay")

		_, err := e.svc.Update(ctx, u, Selector{Tags: []string{"team:pay"}}, Change{AddTags: []string{"env:qa"}}, false)
		var de *Error
		if !errors.As(err, &de) || de.Code != access.CodeClash || len(de.Items) == 0 {
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
		if _, err := e.svc.Update(ctx, u, Selector{Tags: []string{"team:pay"}}, Change{Rename: "X"}, false); code(err) != access.CodeNeedsOne {
			t.Fatalf("rename of several: %v", err)
		}
		if _, err := e.svc.Update(ctx, u, Selector{Name: "PAY_TOKEN"}, Change{Rename: "STRIPE_KEY", RemoveTags: []string{"region:eu"}}, false); code(err) != access.CodeClash {
			t.Fatalf("rename onto an existing identity: %v", err)
		}
		if _, err := e.svc.Update(ctx, u, Selector{Name: "PAY_TOKEN"}, Change{Rename: "PAY_KEY"}, false); err != nil {
			t.Fatal(err)
		}
		// moving a secret out of the actor's grant is denied
		if _, err := e.svc.Update(ctx, u, Selector{Name: "PAY_KEY"}, Change{RemoveTags: []string{"app:shop"}}, false); code(err) != access.CodeDenied {
			t.Fatalf("moving out of the grant: %v", err)
		}
		if err := e.log.Verify(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAmbiguousName(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")
		e.set(u, "BASE_URL", "a", "app:shop", "env:dev")
		e.set(u, "BASE_URL", "b", "app:shop", "env:prod")
		_, err := e.svc.Run(ctx, u, Selector{Tags: []string{"app:shop"}}, false)
		var de *Error
		if !errors.As(err, &de) || de.Code != access.CodeAmbiguous || len(de.Items) != 2 {
			t.Fatalf("got %v", err)
		}
		if _, err := e.svc.Reveal(ctx, u, Selector{Name: "BASE_URL"}, true); code(err) != access.CodeAmbiguous {
			t.Fatalf("reveal: %v", err)
		}
		if vals, err := e.svc.Run(ctx, u, Selector{Tags: []string{"app:shop", "env:dev"}}, false); err != nil || len(vals) != 1 {
			t.Fatalf("adding a tag resolves it: %v", err)
		}
	})
}

func TestAuthorizeAndMachines(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
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
		if _, err := e.svc.Run(ctx, u, Selector{Tags: []string{"app:shop"}}, false); code(err) != access.CodeStepUp {
			t.Fatalf("run with a requires_authorize secret: %v", err)
		}
		if vals, err := e.svc.Run(ctx, u, Selector{Tags: []string{"app:shop"}}, true); err != nil || len(vals) != 2 {
			t.Fatalf("run with step-up: %v", err)
		}
		if _, err := e.svc.Update(ctx, u, sel, Change{Authorize: &off}, false); code(err) != access.CodeStepUp {
			t.Fatalf("authorize off needs step-up: %v", err)
		}

		m := e.machine(u)
		e.grant(m, "read", "app:shop")
		if _, err := e.svc.Reveal(ctx, m, Selector{Name: "LOG_LEVEL"}, true); code(err) != access.CodeDenied {
			t.Fatalf("machines never reveal: %v", err)
		}
		if _, err := e.svc.Run(ctx, m, Selector{Tags: []string{"env:dev"}}, false); err != nil {
			t.Fatalf("machine run of a plain secret: %v", err)
		}
		if _, err := e.svc.Run(ctx, m, Selector{Name: "STRIPE_KEY"}, true); code(err) != access.CodeDenied {
			t.Fatalf("machines cannot run requires_authorize secrets: %v", err)
		}
		// a machine never exceeds its owner: grant it more than the owner has
		m2 := e.machine(u)
		e.grant(m2, "read", "app:billing")
		other := e.human("member")
		e.grant(other, "write", "app:billing")
		e.set(other, "BILL", "v", "app:billing")
		if _, err := e.svc.Run(ctx, m2, Selector{Name: "BILL"}, false); code(err) != access.CodeNotFound {
			t.Fatalf("machine beyond its owner sees nothing: %v", err)
		}
	})
}

func TestArchiveHidesAndFreesIdentity(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
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
		if _, err := e.svc.Run(ctx, u, Selector{Name: "OLD"}, false); code(err) != access.CodeNotFound {
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
		ctx := t.Context()
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")
		set := func(in SetInput) error {
			in.Create = true
			in.Tags = []string{"app:shop"}
			_, err := e.svc.Set(ctx, u, in)
			return err
		}
		if code(set(SetInput{Name: "BIG", Value: make([]byte, MaxText+1)})) != access.CodeInvalid {
			t.Fatal("text over 64 KB")
		}
		if err := set(SetInput{Name: "BIG", Value: make([]byte, MaxText)}); err != nil {
			t.Fatal(err)
		}
		if code(set(SetInput{Name: "F", Kind: "file", Filename: "a.pem", Value: make([]byte, MaxFile+1)})) != access.CodeInvalid {
			t.Fatal("file over 1 MB")
		}
		if err := set(SetInput{Name: "F", Kind: "file", Filename: "../../a.pem", Value: []byte("x")}); err != nil {
			t.Fatal(err)
		}
		v, err := e.svc.Reveal(ctx, u, Selector{Name: "F"}, true)
		if err != nil || v.Filename != "a.pem" {
			t.Fatalf("file name must be reduced to its base: %q %v", v.Filename, err)
		}
		if code(set(SetInput{Name: "bad name", Value: []byte("x")})) != access.CodeInvalid {
			t.Fatal("bad name")
		}
		if code(set(SetInput{Name: "E"})) != access.CodeInvalid {
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

// rewrap runs RewrapTx in its own transaction, as a rotation does.
func rewrap(ctx context.Context, p storage.Provider, svc *Service, by uuid.UUID, totp int) (n int, err error) {
	err = storage.InTx(ctx, p, func(tx *sql.Tx) (err error) {
		n, err = svc.RewrapTx(ctx, tx, by, totp)
		return err
	})
	return n, err
}

func TestKeyRotationRewrapsWithoutTouchingCiphertext(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		u := e.human("member")
		admin := e.human("admin")
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

		// A rewrap that fails leaves no audit row: the row and the rewrap commit together.
		onlyV2, _ := keys.ParseMasterKeys(k2)
		if _, err := rewrap(ctx, p, New(p, onlyV2, e.log), admin.ID, 0); err == nil {
			t.Fatal("a ring without the key of existing data must fail")
		}
		if e.auditCount(admin, "key_rotate", "ok") != 0 {
			t.Fatal("a failed rewrap must not be audited as a rotation")
		}

		if n, err := rewrap(ctx, p, svc2, admin.ID, 3); err != nil || n != 1 {
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
		rows, err := e.log.List(ctx, audit.Filter{}, 100)
		if err != nil {
			t.Fatal(err)
		}
		var rot []audit.Row
		for _, r := range rows {
			if r.Action == "key_rotate" {
				rot = append(rot, r)
			}
		}
		if len(rot) != 1 || rot[0].Principal != admin.ID || rot[0].TargetType != "key" || rot[0].Metadata["key_id"] != "manual:v2" ||
			fmt.Sprint(rot[0].Metadata["secret_versions"]) != "1" || fmt.Sprint(rot[0].Metadata["totp"]) != "3" {
			t.Fatalf("the rotation must be audited once, with its counts: %+v", rot)
		}
		if v, err := svc2.Reveal(ctx, u, Selector{Name: "ROT"}, true); err != nil || string(v.Data) != fakeValue {
			t.Fatalf("readable after rewrap: %v", err)
		}
		if n, _ := rewrap(ctx, p, svc2, admin.ID, 0); n != 0 {
			t.Fatal("nothing left to rewrap")
		}
		if err := e.log.Verify(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

// Turning confirmation off needs a confirmation, but only for someone who may change the secret at all: a person
// with a read-only grant is refused outright and must never be sent through a confirmation first.
func TestAuthorizeOffChecksPermissionBeforeConfirmation(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		owner := e.human("member")
		e.grant(owner, "write", "app:shop")
		e.set(owner, "STRIPE_KEY", fakeValue, "app:shop")
		reader := e.human("member")
		e.grant(reader, "read", "app:shop")
		off := false

		if _, err := e.svc.Update(ctx, reader, Selector{Name: "STRIPE_KEY"}, Change{Authorize: &off}, false); code(err) != access.CodeDenied {
			t.Fatalf("a read-only person must be refused, not asked to confirm: %v", err)
		}
		if e.auditCount(reader, "update", "denied") != 1 {
			t.Fatal("the refusal is audited")
		}
		stranger := e.human("member") // no grant at all: the secret does not exist for them
		if _, err := e.svc.Update(ctx, stranger, Selector{Name: "STRIPE_KEY"}, Change{Authorize: &off}, false); code(err) != access.CodeNotFound {
			t.Fatalf("no grant: %v", err)
		}
		// the owner still needs the confirmation, and a machine can never give one
		if _, err := e.svc.Update(ctx, owner, Selector{Name: "STRIPE_KEY"}, Change{Authorize: &off}, false); code(err) != access.CodeStepUp {
			t.Fatalf("the owner is asked to confirm: %v", err)
		}
		m := e.machine(owner)
		e.grant(m, "write", "app:shop")
		if _, err := e.svc.Update(ctx, m, Selector{Name: "STRIPE_KEY"}, Change{Authorize: &off}, true); code(err) != access.CodeDenied {
			t.Fatalf("a machine can never turn confirmation off: %v", err)
		}
	})
}

// race runs fn n times at once and returns each call's error.
func race(n int, fn func(i int) error) []error {
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			<-start
			errs[i] = fn(i)
		})
	}
	close(start)
	wg.Wait()
	return errs
}

// Writers of one secret take turns: every one of them succeeds and gets its own version number.
func TestConcurrentSetsOfOneSecret(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")
		e.set(u, "CONC", "v0-FAKE", "app:shop")

		const n = 8
		versions := make([]int, n)
		for i, err := range race(n, func(i int) error {
			r, err := e.svc.Set(ctx, u, SetInput{Name: "CONC", Tags: []string{"app:shop"}, Value: fmt.Appendf(nil, "v%d-FAKE", i)})
			versions[i] = r.Version
			return err
		}) {
			if err != nil {
				t.Fatalf("writer %d: %v", i, err)
			}
		}
		slices.Sort(versions)
		for i, v := range versions {
			if v != i+2 {
				t.Fatalf("versions %v, want 2..%d", versions, n+1)
			}
		}
		if err := e.log.Verify(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

// Of several creators of one new identity, one creates it and the others either add a version to it or are told
// to retry; none gets a database error.
func TestConcurrentCreatesOfOneSecret(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")

		const n = 8
		versions := make([]int, n)
		var created int
		var mu sync.Mutex
		ok := 0
		for i, err := range race(n, func(i int) error {
			r, err := e.svc.Set(ctx, u, SetInput{Name: "FRESH", Tags: []string{"app:shop"}, Value: fmt.Appendf(nil, "v%d-FAKE", i), Create: true})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				ok++
				versions[i] = r.Version
				if r.Created {
					created++
				}
			}
			return err
		}) {
			if err != nil && code(err) != access.CodeClash {
				t.Fatalf("creator %d: want success or a retryable clash, got %v", i, err)
			}
		}
		var rows, vers int
		if err := p.DB().QueryRow(`SELECT COUNT(*) FROM secrets`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if err := p.DB().QueryRow(`SELECT COUNT(*) FROM secret_versions`).Scan(&vers); err != nil {
			t.Fatal(err)
		}
		if rows != 1 || created != 1 || vers != ok {
			t.Fatalf("secrets %d, creations %d, versions %d for %d successes", rows, created, vers, ok)
		}
		if err := e.log.Verify(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

// Two renames onto one identity: one wins, the other gets a clash, not a database error.
func TestConcurrentRenamesClash(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")
		e.set(u, "FIRST", "v", "app:shop")
		e.set(u, "SECOND", "v", "app:shop")

		errs := race(2, func(i int) error {
			_, err := e.svc.Update(ctx, u, Selector{Name: []string{"FIRST", "SECOND"}[i]}, Change{Rename: "TARGET"}, false)
			return err
		})
		wins := 0
		for _, err := range errs {
			switch code(err) {
			case "<nil>":
				wins++
			case access.CodeClash:
			default:
				t.Fatalf("want success or a clash, got %v", err)
			}
		}
		if wins != 1 {
			t.Fatalf("exactly one rename wins, got %d: %v", wins, errs)
		}
	})
}

// lockProbe is a key provider that notes, at every unwrap, whether the audit lock is held by someone else. On
// Postgres the lock is an advisory transaction lock; on sqlite there is none and the probe only counts.
type lockProbe struct {
	keys.KeyProvider
	p       storage.Provider
	kind    string
	unwraps int
	held    bool
}

func (l *lockProbe) Unwrap(ctx context.Context, keyID string, wrapped, aad []byte) ([]byte, error) {
	l.unwraps++
	if l.kind == "postgres" {
		tx, err := l.p.DB().BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		var got bool
		const auditLockKey = 7266011 // storage's LockAudit
		if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock($1)`, auditLockKey).Scan(&got); err != nil {
			return nil, err
		}
		l.held = l.held || !got
	}
	return l.KeyProvider.Unwrap(ctx, keyID, wrapped, aad)
}

// Decrypting may mean a network call to KMS; it must happen before the first audit append, which takes the global lock.
func TestRunDecryptsBeforeTheAuditLock(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")
		e.set(u, "ONE", "a-FAKE", "app:shop")
		e.set(u, "TWO", "b-FAKE", "app:shop")

		probe := &lockProbe{KeyProvider: e.svc.kp, p: p, kind: kind}
		svc := New(p, probe, e.log)
		vals, err := svc.Run(ctx, u, Selector{Tags: []string{"app:shop"}}, false)
		if err != nil || len(vals) != 2 || probe.unwraps != 2 {
			t.Fatalf("run: %d values, %d unwraps, %v", len(vals), probe.unwraps, err)
		}
		if probe.held {
			t.Fatal("the audit lock was held while a secret was being decrypted")
		}
		if e.auditCount(u, "read", "ok") != 2 {
			t.Fatal("one audit row per secret read")
		}
	})
}
