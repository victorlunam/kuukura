package main

import (
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

// In a folder linked with `ku link <app>` every `ku secret` command uses app:<app>, like `ku run`, unless the
// command names another app: tag.
func TestSecretCommandsUseTheLinkedApp(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, admin := userWorld(t, p)
		w.grant(admin, "dev@example.test", "write", "app:demo")
		mustOK(t, w.ku("v\n", false, nil, "secret", "set", "SHOP_KEY", "app:shop", "--yes"))

		work := t.TempDir()
		env := map[string]string{"CWD": work}
		mustOK(t, w.ku("", false, env, "link", "demo"))
		const status = "app: demo (linked folder)\n"

		// set without tags carries the linked app
		r := mustOK(t, w.ku(fakeValue+"\n", false, env, "secret", "set", "DB_USERNAME", "--yes"))
		if !strings.Contains(r.errOut, status) || !strings.Contains(r.errOut, "✓ Saved DB_USERNAME (version 1)") {
			t.Fatalf("set:\n%q", r.errOut)
		}
		noValue(t, r, fakeValue)

		// list shows only the app's secrets, and says why
		r = mustOK(t, w.ku("", false, env, "secret", "list"))
		if !strings.Contains(r.errOut, status) || !strings.Contains(r.out, "DB_USERNAME") || !strings.Contains(r.out, "app:demo") || strings.Contains(r.out, "SHOP_KEY") {
			t.Fatalf("list:\n%q\n%q", r.out, r.errOut)
		}

		// an explicit app: tag wins over the link, and no app line is printed
		r = mustOK(t, w.ku("", false, env, "secret", "list", "app:shop"))
		if strings.Contains(r.errOut, "app: ") || !strings.Contains(r.out, "SHOP_KEY") || strings.Contains(r.out, "DB_USERNAME") {
			t.Fatalf("explicit app:\n%q\n%q", r.out, r.errOut)
		}

		// get, update, revoke and archive select inside the linked app
		mustOK(t, w.ku("v\n", false, nil, "secret", "set", "DB_USERNAME", "app:shop", "--yes"))
		r = mustOK(t, w.ku("", false, env, "secret", "update", "DB_USERNAME", "+env:dev"))
		if !strings.Contains(r.errOut, status) {
			t.Fatalf("update:\n%q", r.errOut)
		}
		if r := mustOK(t, w.ku("", false, env, "secret", "list", "env:dev")); !strings.Contains(r.out, "app:demo env:dev") {
			t.Fatalf("updated:\n%q", r.out)
		}
		r = mustOK(t, w.ku("", false, env, "secret", "revoke", "DB_USERNAME"))
		if !strings.Contains(r.errOut, status) || !strings.Contains(r.errOut, "✓ Revoked DB_USERNAME") {
			t.Fatalf("revoke:\n%q", r.errOut)
		}
		mustOK(t, w.ku("", false, env, "secret", "archive", "DB_USERNAME"))
		if r := w.ku("", false, env, "secret", "get", "DB_USERNAME", "--reveal"); !strings.Contains(r.errOut, status) {
			t.Fatalf("get:\n%q", r.errOut)
		}
		// the other app's secret of the same name was never touched
		if r := mustOK(t, w.ku("", false, nil, "secret", "list", "DB_USERNAME")); !strings.Contains(r.out, "app:shop") {
			t.Fatalf("shop copy:\n%q", r.out)
		}
	})
}

func TestDeniedWriteSaysWhichTagsAndHowToGetAccess(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p) // dev can write app:shop only
		env := map[string]string{"CWD": t.TempDir()}
		mustOK(t, w.ku("", false, env, "link", "darwin-cloud"))
		want := "✗ You can't write secrets tagged app:darwin-cloud.\n  Ask an admin: ku workspace grant <you> write app:darwin-cloud\n"

		r := w.ku(fakeValue+"\n", false, env, "secret", "set", "DB_USERNAME", "--yes")
		if r.code != 1 || !strings.HasSuffix(r.errOut, want) {
			t.Fatalf("set:\n%q", r.errOut)
		}
		noValue(t, r, fakeValue)

		// explicit tags are named as typed, not the link's
		r = w.ku(fakeValue+"\n", false, env, "secret", "set", "DB_USERNAME", "app:billing", "env:dev", "--yes")
		if r.code != 1 || !strings.HasSuffix(r.errOut, "✗ You can't write secrets tagged app:billing env:dev.\n  Ask an admin: ku workspace grant <you> write app:billing env:dev\n") {
			t.Fatalf("explicit:\n%q", r.errOut)
		}
	})
}

// Nobody can write a secret without tags (a grant always names one), so the value is not even asked for.
func TestSetWithoutTagsInAnUnlinkedFolderFailsBeforeAskingForTheValue(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p)
		// no stdin: reading the value would fail with "the value is empty" instead
		r := w.ku("", false, nil, "secret", "set", "DB_USERNAME")
		want := "✗ A secret needs at least one tag you can write, e.g. app:<app>.\n  Run: ku link <app>\n"
		if r.code != 1 || !strings.HasSuffix(r.errOut, want) || strings.Contains(r.errOut, "empty") {
			t.Fatalf("tagless:\n%q", r.errOut)
		}
	})
}
