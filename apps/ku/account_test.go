package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

var factorLine = regexp.MustCompile(`(?m)^([0-9a-f]{8})  (passkey|authenticator app)`)

// A person with a passkey can add an authenticator app and another passkey, see them, and remove one; the last
// one stays. Each change needs a confirmation with a current second step.
func TestAccountFactors(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w := newWorld(t, p)
		admin := w.admin()
		user := w.member(admin, "dev@example.test")
		w.loginAs(user)

		list := func() [][]string {
			return factorLine.FindAllStringSubmatch(mustOK(t, w.ku("", false, nil, "account", "factor", "list")).out, -1)
		}
		if l := list(); len(l) != 1 || l[0][2] != "passkey" {
			t.Fatalf("starts with the enrollment passkey: %v", l)
		}

		// add an authenticator app: confirms first, then the browser registers it
		r := mustOK(t, w.ku("", false, nil, "account", "factor", "add", "totp"))
		if w.stepUps != 1 || !strings.Contains(r.errOut, "✓ Added the authenticator app") || !strings.Contains(r.errOut, "/account/add?id=") {
			t.Fatalf("add totp: steps=%d out=%q err=%q", w.stepUps, r.out, r.errOut)
		}
		mustOK(t, w.ku("", false, nil, "account", "factor", "add", "passkey"))
		if w.stepUps != 2 {
			t.Fatalf("every add confirms: %d", w.stepUps)
		}
		l := list()
		if len(l) != 3 {
			t.Fatalf("three factors: %v", l)
		}

		// the added factor really works: it can confirm a command on its own
		delete(w.devs, "dev@example.test")
		w.grant(admin, "dev@example.test", "write", "app:shop")
		mustOK(t, w.ku("v\n", false, nil, "secret", "set", "DEMO_KEY", "app:shop", "--yes"))
		if r := mustOK(t, w.ku("", false, nil, "secret", "get", "DEMO_KEY", "--reveal")); r.out != "v" {
			t.Fatalf("an added factor confirms: %q", r.out)
		}

		// remove: asks first, confirms, and an unknown or ambiguous id changes nothing
		if r := w.ku("", false, nil, "account", "factor", "remove", "zzzz", "--yes"); r.code == 0 || !strings.Contains(r.errOut, "No passkey or authenticator app starts with") || !strings.Contains(r.errOut, "  Run: ku account factor list") {
			t.Fatalf("unknown id: %q", r.errOut)
		}
		if r := w.ku("", false, nil, "account", "factor", "remove", "", "--yes"); r.code == 0 || !strings.Contains(r.errOut, "more than one") {
			t.Fatalf("an empty id matches everything and must not remove: %q", r.errOut)
		}
		if r := w.ku("", false, nil, "account", "factor", "remove", l[1][1]); r.code == 0 || !strings.Contains(r.errOut, "--yes") {
			t.Fatalf("no terminal and no --yes must refuse: %q", r.errOut)
		}
		before := w.stepUps
		mustOK(t, w.ku("", false, nil, "account", "factor", "remove", l[1][1], "--yes"))
		mustOK(t, w.ku("", false, nil, "account", "factor", "remove", l[2][1], "--yes"))
		if w.stepUps != before+2 || len(list()) != 1 {
			t.Fatalf("removed with a confirmation each: steps=%d", w.stepUps-before)
		}

		// the last one cannot be removed, and no confirmation is wasted on it
		before = w.stepUps
		last := list()[0][1]
		if r := w.ku("", false, nil, "account", "factor", "remove", last, "--yes"); r.code == 0 || !strings.Contains(r.errOut, "only passkey or authenticator app") || w.stepUps != before {
			t.Fatalf("last factor: %q", r.errOut)
		}

		// the audit trail records what changed, never a secret
		var rows []map[string]any
		_, m := w.api(admin, "GET", "/workspace/audit?limit=100", nil)
		for _, x := range m["rows"].([]any) {
			if row := x.(map[string]any); row["target_type"] == "principal" {
				rows = append(rows, row["metadata"].(map[string]any))
			}
		}
		added, removed := 0, 0
		for _, md := range rows {
			switch md["change"] {
			case "added":
				added++
			case "removed":
				removed++
			}
		}
		if added != 2 || removed != 2 {
			t.Fatalf("audit: added=%d removed=%d", added, removed)
		}
	})
}

// The endpoints themselves: they need the confirmation, the link works once and only for its kind, nobody can
// touch another person's factors, and machines have none.
func TestAccountFactorEndpoints(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w := newWorld(t, p)
		admin := w.admin()
		user := w.member(admin, "dev@example.test")
		other := w.member(admin, "other@example.test")

		// no confirmation, no new factor and no removal
		code, m := w.api(user, "POST", "/account/factors", map[string]string{"kind": "totp"})
		if code != 403 || m["code"] != "step-up-required" {
			t.Fatalf("add without confirmation: %d %v", code, m)
		}
		_, fl := w.api(user, "GET", "/account/factors", nil)
		id := fl["factors"].([]any)[0].(map[string]any)["id"].(string)
		if code, m := w.api(user, "DELETE", "/account/factors/"+id, nil); code != 403 || m["code"] != "step-up-required" {
			t.Fatalf("remove without confirmation: %d %v", code, m)
		}
		if code, _ := w.api(user, "POST", "/account/factors", map[string]string{"kind": "sms"}); code != 400 {
			t.Fatalf("unknown kind: %d", code)
		}

		// someone else's factor is not found, even with a valid confirmation of my own
		// (the CLI cannot even name it: it only lists the caller's own factors, so the request goes to the API directly)
		_, ol := w.api(other, "GET", "/account/factors", nil)
		otherID := ol["factors"].([]any)[0].(map[string]any)["id"].(string)
		w.loginAs(user)
		mustOK(t, w.ku("", false, nil, "account", "factor", "add", "totp")) // so that the caller has a second factor to spare
		_, st := w.api(user, "POST", "/auth/stepup", map[string]string{"purpose": "factor_remove", "subject": otherID, "profile": "default"})
		if err := w.browser(st["url"].(string)); err != nil {
			t.Fatal(err)
		}
		grant := st["id"].(string)
		if code, m := w.api(user, "DELETE", "/account/factors/"+otherID, nil, "X-Step-Up", grant); code != 404 {
			t.Fatalf("another person's factor, with my own valid confirmation: %d %v", code, m)
		}
		_, ol = w.api(other, "GET", "/account/factors", nil)
		if len(ol["factors"].([]any)) != 1 {
			t.Fatal("the other person still has their factor")
		}

		// a machine has no second steps and no way to add one
		_, inv := w.api(admin, "POST", "/workspace/invites", map[string]any{"name": "ci", "machine": true})
		mtok := inv["token"].(string)
		if code, _ := w.api(mtok, "GET", "/account/factors", nil); code != 403 {
			t.Fatalf("machine list: %d", code)
		}
		if code, _ := w.api(mtok, "POST", "/account/factors", map[string]string{"kind": "totp"}); code != 403 {
			t.Fatalf("machine add: %d", code)
		}
	})
}

// The add link works once, a session made for one kind cannot register the other, and it is not a login.
func TestAddLinkIsOneShotAndForItsKind(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w := newWorld(t, p)
		admin := w.admin()
		w.member(admin, "dev@example.test")
		in, _ := w.tokens.Validate(t.Context(), w.member(admin, "dev2@example.test"))

		id, err := w.auth.StartAddFactor(in, "passkey")
		if err != nil {
			t.Fatal(err)
		}
		pd, err := w.auth.OpenAddFactor(t.Context(), id)
		if err != nil || pd.Mode != "add" || pd.Add != "passkey" {
			t.Fatalf("open: %+v %v", pd, err)
		}
		if _, err := w.auth.OpenAddFactor(t.Context(), id); err == nil {
			t.Fatal("the link must work once")
		}
		mid, _ := w.tokens.Validate(t.Context(), pd.Token)
		if _, _, err := w.auth.BeginTOTP(t.Context(), mid); err == nil {
			t.Fatal("a passkey session must not register an authenticator app")
		}
		if _, err := w.auth.BeginPasskeyRegistration(t.Context(), mid); err != nil {
			t.Fatal(err)
		}
		// the short session cannot read secrets
		if code, _ := w.api(pd.Token, "GET", "/secrets", nil); code != 401 && code != 403 {
			t.Fatalf("an enroll session is not an API session: %d", code)
		}
		if _, err := w.auth.StartAddFactor(in, "sms"); err == nil {
			t.Fatal("unknown kind")
		}
	})
}
