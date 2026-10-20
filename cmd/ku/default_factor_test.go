package main

import (
	"io"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

// The first factor is the default; the person can move the mark; the confirmation offers the default first;
// removing the default hands the mark to another factor; nobody can mark someone else's.
func TestDefaultFactor(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w := newWorld(t, p)
		admin := w.admin()
		user := w.member(admin, "dev@example.test")
		other := w.member(admin, "other@example.test")
		w.loginAs(user)

		list := func() [][]string {
			return factorLine.FindAllStringSubmatch(mustOK(t, w.ku("", false, nil, "account", "factor", "list")).out, -1)
		}
		defaults := func() (n int, kinds string) {
			for _, line := range strings.Split(mustOK(t, w.ku("", false, nil, "account", "factor", "list")).out, "\n") {
				if strings.HasSuffix(line, "default") {
					n++
					kinds += strings.Fields(line)[1]
				}
			}
			return
		}

		if n, k := defaults(); n != 1 || k != "passkey" {
			t.Fatalf("the enrollment passkey is the default: %d %s", n, k)
		}
		mustOK(t, w.ku("", false, nil, "account", "factor", "add", "totp"))
		if n, k := defaults(); n != 1 || k != "passkey" {
			t.Fatalf("adding a factor keeps the default: %d %s", n, k)
		}
		_, st := w.api(user, "POST", "/auth/stepup", map[string]string{"purpose": "reveal", "subject": "A"})
		if m := st["methods"].([]any); m[0] != "passkey" {
			t.Fatalf("the passkey is offered first: %v", m)
		}

		var app string // created within the same second, so the list order is not the creation order
		for _, l := range list() {
			if l[2] == "app" {
				app = l[1]
			}
		}
		r := mustOK(t, w.ku("", false, nil, "account", "factor", "default", app))
		if !strings.Contains(r.out, "default") {
			t.Fatalf("default: %q", r.out)
		}
		if n, k := defaults(); n != 1 || k != "app" {
			t.Fatalf("exactly one default, now the app: %d %s", n, k)
		}
		_, st = w.api(user, "POST", "/auth/stepup", map[string]string{"purpose": "reveal", "subject": "A"})
		m := st["methods"].([]any)
		if m[0] != "totp" || m[1] != "passkey" {
			t.Fatalf("the default comes first: %v", m)
		}
		resp, err := w.srv.Client().Get(w.srv.URL + "/stepup?id=" + st["id"].(string))
		if err != nil {
			t.Fatal(err)
		}
		pb, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		page := string(pb)
		if i, j := strings.Index(page, `id="f-totp"`), strings.Index(page, `id="pk"`); i < 0 || j < 0 || i > j {
			t.Fatalf("the page shows the code first, then the passkey: %d %d", i, j)
		}

		// removing the default hands the mark over
		mustOK(t, w.ku("", false, nil, "account", "factor", "remove", app, "--yes"))
		if n, k := defaults(); n != 1 || k != "passkey" {
			t.Fatalf("the remaining factor becomes the default: %d %s", n, k)
		}

		// someone else's factor, a wrong body and machines are refused
		_, ol := w.api(other, "GET", "/account/factors", nil)
		otherID := ol["factors"].([]any)[0].(map[string]any)["id"].(string)
		if code, _ := w.api(user, "PATCH", "/account/factors/"+otherID, map[string]bool{"default": true}); code != 404 {
			t.Fatalf("another person's factor: %d", code)
		}
		_, ml := w.api(user, "GET", "/account/factors", nil)
		mine := ml["factors"].([]any)[0].(map[string]any)["id"].(string)
		if code, _ := w.api(user, "PATCH", "/account/factors/"+mine, map[string]bool{"default": false}); code != 400 {
			t.Fatalf("default:false: %d", code)
		}
		_, inv := w.api(admin, "POST", "/workspace/invites", map[string]any{"name": "ci", "machine": true})
		if code, _ := w.api(inv["token"].(string), "PATCH", "/account/factors/"+mine, map[string]bool{"default": true}); code != 403 {
			t.Fatalf("machine: %d", code)
		}
	})
}
