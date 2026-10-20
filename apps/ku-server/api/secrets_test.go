package api_test

import (
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

func TestSecretsOverHTTP(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		admin, _ := e.admin()
		user, dev := e.member(admin, "dev@example.test")

		// deny by default; the admin role grants no secret access
		e.problem(e.do("POST", "/secrets/versions", user, map[string]any{"name": "STRIPE_KEY", "tags": []string{"app:shop"}, "value": fakeValue, "create": true}), 403, "forbidden")
		e.problem(e.do("POST", "/secrets/versions", admin, map[string]any{"name": "STRIPE_KEY", "tags": []string{"app:shop"}, "value": fakeValue, "create": true}), 403, "forbidden")

		if r := e.do("POST", "/workspace/grants", admin, map[string]any{"subject": "dev@example.test", "permission": "write", "tags": []string{"app:shop"}}); r.Code != 201 {
			t.Fatalf("grant: %d %s", r.Code, r.Body)
		}
		e.problem(e.do("POST", "/workspace/grants", user, map[string]any{"subject": "dev@example.test", "permission": "write", "tags": []string{"app:shop"}}), 403, "forbidden")

		body := map[string]any{"name": "stripe_key", "tags": []string{"app:shop", "env:prod"}, "value": fakeValue}
		e.problem(e.do("POST", "/secrets/versions", user, body), 409, "needs-confirmation")
		body["create"] = true
		if r := e.do("POST", "/secrets/versions", user, body); r.Code != 201 || r.json()["version"] != float64(1) {
			t.Fatalf("create: %d %s", r.Code, r.Body)
		}
		if r := e.do("POST", "/secrets/versions", user, body); r.Code != 200 || r.json()["version"] != float64(2) {
			t.Fatalf("new version: %d %s", r.Code, r.Body)
		}

		l := e.do("GET", "/secrets?tags=app:shop", user, nil)
		if l.Code != 200 || strings.Contains(l.Body.String(), fakeValue) || !strings.Contains(l.Body.String(), `"STRIPE_KEY"`) {
			t.Fatalf("list: %d %s", l.Code, l.Body)
		}
		if strings.Contains(l.Body.String(), "value") {
			t.Fatal("a list never has a value column, not even masked")
		}

		// reveal needs a step-up bound to this request
		sel := map[string]any{"name": "STRIPE_KEY", "tags": []string{"env:prod"}}
		e.problem(e.do("POST", "/secrets/reveal", user, sel), 403, "step-up-required")
		e.problem(e.do("POST", "/secrets/reveal", user, sel, "X-Step-Up", "bogus"), 403, "step-up-required")
		wrong := e.stepUp(user, dev, "reveal", "OTHER")
		e.problem(e.do("POST", "/secrets/reveal", user, sel, "X-Step-Up", wrong), 403, "step-up-required")
		id := e.stepUp(user, dev, "reveal", "STRIPE_KEY env:prod")
		r := e.do("POST", "/secrets/reveal", user, sel, "X-Step-Up", id)
		if r.Code != 200 || r.json()["value"] != fakeValue || r.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("reveal: %d %s", r.Code, r.Body)
		}
		e.problem(e.do("POST", "/secrets/reveal", user, sel, "X-Step-Up", id), 403, "step-up-required") // single use

		// run: plain secrets need no step-up; requires_authorize does
		runSel := map[string]any{"tags": []string{"app:shop"}}
		if r := e.do("POST", "/run", user, runSel); r.Code != 200 || !strings.Contains(r.Body.String(), fakeValue) {
			t.Fatalf("run: %d %s", r.Code, r.Body)
		}
		if r := e.do("PATCH", "/secrets", user, map[string]any{"selector": map[string]any{"name": "STRIPE_KEY"}, "requires_authorize": true}); r.Code != 200 {
			t.Fatalf("authorize on: %d %s", r.Code, r.Body)
		}
		e.problem(e.do("POST", "/run", user, runSel), 403, "step-up-required")
		rid := e.stepUp(user, dev, "run", "app:shop")
		if r := e.do("POST", "/run", user, runSel, "X-Step-Up", rid); r.Code != 200 {
			t.Fatalf("run with step-up: %d %s", r.Code, r.Body)
		}
		// authorize off needs one too
		off := map[string]any{"selector": map[string]any{"name": "STRIPE_KEY"}, "requires_authorize": false}
		e.problem(e.do("PATCH", "/secrets", user, off), 403, "step-up-required")
		oid := e.stepUp(user, dev, "authorize_off", "STRIPE_KEY")
		if r := e.do("PATCH", "/secrets", user, off, "X-Step-Up", oid); r.Code != 200 {
			t.Fatalf("authorize off: %d %s", r.Code, r.Body)
		}

		// revoke blocks until the next set
		if r := e.do("POST", "/secrets/revoke", user, map[string]any{"name": "STRIPE_KEY"}); r.Code != 200 {
			t.Fatalf("revoke: %d %s", r.Code, r.Body)
		}
		p1 := e.do("POST", "/run", user, map[string]any{"name": "STRIPE_KEY", "tags": []string{"env:prod"}})
		e.problem(p1, 409, "blocked")
		if items, _ := p1.json()["items"].([]any); len(items) != 1 {
			t.Fatalf("the blocked secret is named: %s", p1.Body)
		}
		body["value"] = "new-FAKE"
		if r := e.do("POST", "/secrets/versions", user, body); r.Code != 200 {
			t.Fatal(r.Body)
		}
		if r := e.do("POST", "/run", user, runSel); r.Code != 200 || !strings.Contains(r.Body.String(), "new-FAKE") {
			t.Fatalf("after set: %s", r.Body)
		}

		// archive via PATCH
		if r := e.do("PATCH", "/secrets", user, map[string]any{"selector": map[string]any{"name": "STRIPE_KEY"}, "archived": true}); r.Code != 200 {
			t.Fatalf("archive: %s", r.Body)
		}
		e.problem(e.do("POST", "/run", user, map[string]any{"name": "STRIPE_KEY"}), 404, "not-found")

		// no value ever reaches the logs
		if strings.Contains(e.logs.String(), fakeValue) || strings.Contains(e.logs.String(), "new-FAKE") {
			t.Fatal("a value leaked into the logs")
		}
		if !strings.Contains(e.logs.String(), `"route":"/secrets/reveal"`) {
			t.Fatal("requests are logged by route")
		}
	})
}
