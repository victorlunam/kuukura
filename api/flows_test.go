package api_test

import (
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

func TestProblemJSONAndTransport(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		e.problem(e.do("GET", "/secrets", "", nil), 401, "unauthorized")
		e.problem(e.do("GET", "/secrets", "ku_bogus", nil), 401, "unauthorized")
		e.problem(e.do("GET", "/nope", "", nil), 401, "unauthorized") // unknown paths do not reveal the route table
		if r := e.do("GET", "/secrets", "", nil, "X-Forwarded-Proto", "-"); r.Code != 400 || r.json()["code"] != "https-required" {
			t.Fatalf("HTTPS is required: %d %s", r.Code, r.Body)
		}
		if r := e.do("GET", "/healthz", "", nil, "X-Forwarded-Proto", "-"); r.Code != 200 || r.Body.String() != "ok" {
			t.Fatalf("healthz needs no auth and no TLS inside the container: %d %q", r.Code, r.Body)
		}
		admin, _ := e.admin()
		e.problem(e.do("POST", "/secrets/versions", admin, "{not json"), 400, "invalid-request")
		e.problem(e.do("POST", "/secrets/versions", admin, `{"name":"A","unknown":1}`), 400, "invalid-request")
		if r := e.do("GET", "/healthz", "", nil); r.Header().Get("Strict-Transport-Security") == "" || r.Header().Get("X-Request-ID") == "" {
			t.Fatal("security headers / request id")
		}
	})
}

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

func TestWorkspaceAdminAndMachines(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		admin, _ := e.admin()
		user, _ := e.member(admin, "dev@example.test")

		e.problem(e.do("GET", "/workspace/audit", user, nil), 403, "forbidden")
		e.problem(e.do("POST", "/workspace/invites", user, map[string]any{"email": "x@example.test"}), 403, "forbidden")
		e.problem(e.do("PATCH", "/workspace/groups/pay", user, map[string]any{"add": []string{"dev@example.test"}}), 403, "forbidden")

		if r := e.do("PATCH", "/workspace/groups/pay", admin, map[string]any{"add": []string{"dev@example.test"}}); r.Code != 204 {
			t.Fatalf("group: %d %s", r.Code, r.Body)
		}
		if r := e.do("POST", "/workspace/grants", admin, map[string]any{"subject": "pay", "permission": "write", "tags": []string{"team:pay"}}); r.Code != 201 {
			t.Fatalf("group grant: %d %s", r.Code, r.Body)
		}
		if r := e.do("POST", "/secrets/versions", user, map[string]any{"name": "PAY", "tags": []string{"team:pay"}, "value": "v", "create": true}); r.Code != 201 {
			t.Fatalf("a group member can write: %d %s", r.Code, r.Body)
		}

		// machine: key shown once, can run, can never reveal
		mi := e.do("POST", "/workspace/invites", admin, map[string]any{"name": "ci-deploy", "machine": true})
		key, _ := mi.json()["token"].(string)
		if mi.Code != 201 || !strings.HasPrefix(key, "ku_") {
			t.Fatalf("machine invite: %d %s", mi.Code, mi.Body)
		}
		e.do("POST", "/workspace/grants", admin, map[string]any{"subject": "ci-deploy", "permission": "read", "tags": []string{"team:pay"}})
		// the machine's owner (admin) has no grants, so the machine reads nothing: it never exceeds its creator
		e.problem(e.do("POST", "/run", key, map[string]any{"name": "PAY"}), 404, "not-found")
		e.problem(e.do("POST", "/secrets/reveal", key, map[string]any{"name": "PAY"}), 404, "not-found")
		// an existing secret the machine may not read is indistinguishable from one that does not exist
		missing := e.do("POST", "/run", key, map[string]any{"name": "NO_SUCH_SECRET"})
		hidden := e.do("POST", "/run", key, map[string]any{"name": "PAY"})
		if missing.Code != hidden.Code || missing.json()["detail"] != hidden.json()["detail"] || hidden.json()["items"] != nil {
			t.Fatalf("unreadable must look like missing: %s vs %s", missing.Body, hidden.Body)
		}
		e.problem(e.do("POST", "/auth/stepup", key, map[string]string{"purpose": "reveal", "subject": "PAY"}), 403, "forbidden")

		// audit is admin-only and holds rows without values
		a := e.do("GET", "/workspace/audit?name=PAY&tags=team:pay", admin, nil)
		if a.Code != 200 || !strings.Contains(a.Body.String(), `"action":"create"`) || !strings.Contains(a.Body.String(), `"secret":"PAY"`) {
			t.Fatalf("audit: %d %s", a.Code, a.Body)
		}

		// disable ends sessions
		if r := e.do("PATCH", "/workspace/identities/"+"dev@example.test", admin, map[string]any{"status": "disabled"}); r.Code != 204 {
			t.Fatalf("disable: %d %s", r.Code, r.Body)
		}
		e.problem(e.do("GET", "/secrets", user, nil), 401, "unauthorized")
		e.problem(e.do("PATCH", "/workspace/identities/root@example.test", admin, map[string]any{"status": "disabled"}), 409, "last-admin")
		e.problem(e.do("PATCH", "/workspace/identities/x", admin, map[string]any{"status": "active"}), 400, "invalid-request")

		// logout invalidates the session
		if r := e.do("POST", "/auth/logout", admin, nil); r.Code != 204 {
			t.Fatalf("logout: %d", r.Code)
		}
		e.problem(e.do("GET", "/secrets", admin, nil), 401, "unauthorized")
		if err := e.log.Verify(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRateLimits(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		pin := "IP"
		ip := "203.0.113.7"
		for i := range 10 {
			if r := e.do("POST", "/auth/token", "", map[string]string{"code": "x", "verifier": "y"}, pin, ip); r.Code != 401 {
				t.Fatalf("request %d: %d", i, r.Code)
			}
		}
		r := e.do("POST", "/auth/token", "", map[string]string{"code": "x", "verifier": "y"}, pin, ip)
		e.problem(r, 429, "quota-exceeded")
		if r.Header().Get("Retry-After") == "" || !strings.Contains(r.Header().Get("RateLimit"), "remaining=0") {
			t.Fatalf("headers: %v", r.Header())
		}
		// another IP is unaffected
		if r := e.do("POST", "/auth/token", "", map[string]string{"code": "x", "verifier": "y"}, pin, "203.0.113.8"); r.Code != 401 {
			t.Fatal("limits are per IP")
		}
		// the bucket refills with time
		e.clock.Add(61)
		if r := e.do("POST", "/auth/token", "", map[string]string{"code": "x", "verifier": "y"}, pin, ip); r.Code != 401 {
			t.Fatalf("after a minute: %d", r.Code)
		}

		// reveal: 10/min per principal
		admin, _ := e.admin()
		user, _ := e.member(admin, "dev@example.test")
		for i := range 10 {
			if r := e.do("POST", "/secrets/reveal", user, map[string]any{"name": "NOPE"}); r.Code == 429 {
				t.Fatalf("reveal %d limited too early", i)
			}
		}
		e.problem(e.do("POST", "/secrets/reveal", user, map[string]any{"name": "NOPE"}), 429, "quota-exceeded")
		if r := e.do("GET", "/secrets", user, nil); r.Code != 200 {
			t.Fatalf("other endpoints keep working: %d", r.Code)
		}
	})
}

func TestPagesAreLockedDown(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		inv, _ := e.ids.BootstrapAdmin(t.Context(), "root@example.test")
		r := e.do("GET", "/invite?token="+inv.Token, "", nil)
		csp := r.Header().Get("Content-Security-Policy")
		if r.Code != 200 || !strings.Contains(csp, "default-src 'none'") || !strings.Contains(r.Body.String(), "/auth/login?go=1&amp;invite=") {
			t.Fatalf("invite page: %d %s", r.Code, csp)
		}
		if r := e.do("GET", "/invite?token=ku_nope", "", nil); r.Code != 404 {
			t.Fatalf("bad invite: %d", r.Code)
		}
		if strings.Contains(e.logs.String(), inv.Token) {
			t.Fatal("invite tokens are never logged")
		}
		// login needs valid CLI parameters unless it is an invite acceptance
		if r := e.do("GET", "/auth/login", "", nil); r.Code != 401 {
			t.Fatalf("login without CLI parameters: %d", r.Code)
		}
	})
}
