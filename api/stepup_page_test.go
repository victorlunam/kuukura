package api_test

import (
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

// The confirmation page offers what the account has, the start response tells the CLI which methods there are,
// and a bad or unknown request never confirms anything.
func TestConfirmationPageAndMethods(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		admin, _ := e.admin()
		user, _ := e.member(admin, "dev@example.test")

		r := e.do("POST", "/auth/stepup", user, map[string]string{"purpose": "reveal", "subject": "A", "profile": "some_name"})
		if r.Code != 201 {
			t.Fatalf("start: %d %s", r.Code, r.Body)
		}
		methods, _ := r.json()["methods"].([]any)
		if len(methods) != 1 || methods[0] != "passkey" {
			t.Fatalf("a passkey account is told it can use a passkey: %v", methods)
		}
		id := r.json()["id"].(string)
		if !strings.Contains(r.json()["url"].(string), "&profile=some_name") {
			t.Fatal("the link carries the profile name")
		}

		page := e.do("GET", "/stepup?id="+id+"&profile=some_name", "", nil)
		body := page.Body.String()
		if page.Code != 200 || !strings.Contains(body, `id="pk"`) || strings.Contains(body, `id="f-totp"`) || !strings.Contains(body, "<small>some_name</small>") {
			t.Fatalf("passkey-only page: %d", page.Code)
		}

		// a profile name that is not plain text never reaches the page; the header falls back to the host
		for _, bad := range []string{"%3Cscript%3Ealert(1)%3C/script%3E", "a%20b", "UPPER"} {
			b := e.do("GET", "/stepup?id="+id+"&profile="+bad, "", nil).Body.String()
			if strings.Contains(b, "<script>alert") || strings.Contains(b, "UPPER") || !strings.Contains(b, "<small>vault.example.test</small>") {
				t.Fatalf("unsafe label %q must fall back", bad)
			}
		}

		// unknown or expired request: a friendly page, not an empty button
		gone := e.do("GET", "/stepup?id=nope", "", nil)
		if gone.Code != 404 || !strings.Contains(gone.Body.String(), "no longer valid") || strings.Contains(gone.Body.String(), `id="pk"`) {
			t.Fatalf("unknown request: %d", gone.Code)
		}

		// a code cannot confirm a request for an account that has no authenticator app, nor an unknown request
		e.problem(e.do("POST", "/stepup/"+id+"/totp", "", map[string]string{"code": "000000"}), 401, "unauthorized")
		e.problem(e.do("POST", "/stepup/nope/totp", "", map[string]string{"code": "000000"}), 401, "unauthorized")
		if d := e.do("GET", "/auth/stepup/"+id, user, nil); d.json()["done"] == true {
			t.Fatal("nothing may be confirmed by those attempts")
		}
	})
}
