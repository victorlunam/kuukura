package api_test

import (
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

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
		e.problem(e.do("PATCH", "/workspace/identities/x", admin, map[string]any{"status": "archived"}), 400, "invalid-request")
		e.problem(e.do("PATCH", "/workspace/identities/x", admin, map[string]any{"status": "active"}), 404, "not-found")
		// enable lifts a disable; the old session stays revoked
		if r := e.do("PATCH", "/workspace/identities/dev@example.test", admin, map[string]any{"status": "active"}); r.Code != 200 || !strings.Contains(r.Body.String(), `"status":"active"`) {
			t.Fatalf("enable: %d %s", r.Code, r.Body)
		}
		e.problem(e.do("GET", "/secrets", user, nil), 401, "unauthorized")
		e.problem(e.do("PATCH", "/workspace/identities/dev@example.test", user, map[string]any{"status": "active"}), 401, "unauthorized")

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
