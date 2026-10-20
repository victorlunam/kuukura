package api_test

import (
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

func TestCreateApp(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		e := setup(t, p)
		admin, _ := e.admin()
		user, _ := e.member(admin, "dev@example.test")
		other, _ := e.member(admin, "other@example.test")

		r := e.do("POST", "/apps", user, map[string]string{"name": "darwin-cloud"})
		if m := r.json(); r.Code != 201 || m["app"] != "darwin-cloud" || m["granted"] != "write" {
			t.Fatalf("create: %d %s", r.Code, r.Body)
		}
		// the creator can write right away; nobody else can see the app
		if r := e.do("POST", "/secrets/versions", user, map[string]any{"name": "K", "tags": []string{"app:darwin-cloud"}, "value": "v", "create": true}); r.Code != 201 {
			t.Fatalf("creator writes: %d %s", r.Code, r.Body)
		}
		e.problem(e.do("POST", "/apps", other, map[string]string{"name": "darwin-cloud"}), 409, "app-exists")
		e.problem(e.do("POST", "/apps", admin, map[string]string{"name": "darwin-cloud"}), 409, "app-exists")
		e.problem(e.do("POST", "/apps", user, map[string]string{"name": "Bad Name"}), 400, "invalid-request")
		e.problem(e.do("POST", "/apps", user, `{"nom":"x"}`), 400, "invalid-request")
		e.problem(e.do("POST", "/apps", "", map[string]string{"name": "x"}), 401, "unauthorized")

		mi := e.do("POST", "/workspace/invites", admin, map[string]any{"name": "ci-deploy", "machine": true})
		key, _ := mi.json()["token"].(string)
		e.problem(e.do("POST", "/apps", key, map[string]string{"name": "ci-app"}), 403, "forbidden")
	})
}
