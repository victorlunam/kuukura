package api_test

import (
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

// The confirmation page says what is being confirmed, in words, and the subject (the person's own text) is escaped.
func TestConfirmationPageSaysWhatItConfirms(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		admin, _ := e.admin()
		user, _ := e.member(admin, "dev@example.test")

		page := func(purpose, subject string) string {
			t.Helper()
			r := e.do("POST", "/auth/stepup", user, map[string]string{"purpose": purpose, "subject": subject})
			if r.Code != 201 {
				t.Fatalf("start %s: %d %s", purpose, r.Code, r.Body)
			}
			g := e.do("GET", "/stepup?id="+r.json()["id"].(string), "", nil)
			if g.Code != 200 {
				t.Fatalf("page %s: %d", purpose, g.Code)
			}
			return g.Body.String()
		}
		for _, c := range []struct{ purpose, subject, want string }{
			{"reveal", "STRIPE_KEY env:prod", "Reveal STRIPE_KEY env:prod"},
			{"run", "STRIPE_KEY env:prod", "Run with STRIPE_KEY env:prod"},
			{"authorize_off", "STRIPE_KEY env:prod", "Turn off confirmation for STRIPE_KEY env:prod"},
			{"factor_add", "passkey", "Add a passkey"},
			{"factor_add", "totp", "Add an authenticator app"},
			{"factor_remove", "8f14e45f-ceea-467a-9575-0cb1c3e0f4f0", "Remove a second step"},
		} {
			if b := page(c.purpose, c.subject); !strings.Contains(b, c.want) {
				t.Fatalf("%s page must say %q", c.purpose, c.want)
			}
		}
		if b := page("reveal", "<b>X</b> env:prod"); strings.Contains(b, "<b>X</b>") || !strings.Contains(b, "Reveal &lt;b&gt;X&lt;/b&gt; env:prod") {
			t.Fatal("the subject is escaped")
		}

		// a request without a subject or with an unknown purpose is refused, and says which
		r := e.do("POST", "/auth/stepup", user, map[string]string{"purpose": "reveal"})
		e.problem(r, 400, "invalid-request")
		if r.json()["detail"] != "Subject is required." {
			t.Fatalf("missing subject: %v", r.json()["detail"])
		}
		r = e.do("POST", "/auth/stepup", user, map[string]string{"purpose": "nope", "subject": "A"})
		e.problem(r, 400, "invalid-request")
		if r.json()["detail"] != "Unknown purpose." {
			t.Fatalf("unknown purpose: %v", r.json()["detail"])
		}
	})
}

// The confirmation pages have their own, wider rate limit: one confirmation is several calls, and the sign-in
// limit would lock a person out after two attempts.
func TestConfirmationRateLimitIsSeparate(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		for i := range 30 {
			if r := e.do("GET", "/stepup?id=nope", "", nil, "IP", "203.0.113.7"); r.Code != 404 {
				t.Fatalf("page %d: %d", i, r.Code)
			}
		}
		for i := range 30 {
			if r := e.do("POST", "/stepup/nope/totp", "", map[string]string{"code": "000000"}, "IP", "203.0.113.7"); r.Code != 404 {
				t.Fatalf("call %d: %d", i, r.Code)
			}
		}
		e.problem(e.do("GET", "/stepup?id=nope", "", nil, "IP", "203.0.113.7"), 429, "quota-exceeded")
		// the sign-in bucket of the same address is untouched
		if r := e.do("POST", "/auth/token", "", map[string]string{"code": "x", "verifier": "y"}, "IP", "203.0.113.7"); r.Code != 401 {
			t.Fatalf("the sign-in limit is separate: %d", r.Code)
		}
	})
}

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
		// a request that is gone (expired, or lost in a server restart) says so, so the page can tell the person to
		// run the command again instead of offering a retry that cannot work
		e.problem(e.do("POST", "/stepup/nope/totp", "", map[string]string{"code": "000000"}), 404, "confirmation-expired")
		e.problem(e.do("POST", "/stepup/nope/begin", "", nil), 404, "confirmation-expired")
		e.problem(e.do("POST", "/stepup/nope/finish", "", "{}"), 404, "confirmation-expired")
		if d := e.do("GET", "/auth/stepup/"+id, user, nil); d.json()["done"] == true {
			t.Fatal("nothing may be confirmed by those attempts")
		}
	})
}
