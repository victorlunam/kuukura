package main

import (
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

// A typo in a flag must not run the command with the flag ignored (--profle would use the default profile).
func TestUnknownFlagsAreRejected(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p)
		for _, args := range [][]string{
			{"secret", "list", "--profle", "work"},
			{"secret", "set", "X", "--yes", "--genrate"},
			{"secret", "get", "X", "--reveel"},
			{"run", "--profle=work", "--", "true"},
			{"account", "factor", "list", "--yess"},
			{"workspace", "audit", "--machine"},
			{"login", "--url", "https://x.example.test"},
		} {
			r := w.ku("", false, nil, args...)
			if r.code != 1 || !strings.Contains(r.errOut, "unknown flag --") {
				t.Errorf("%v: %d %q", args, r.code, r.errOut)
			}
			if strings.Contains(r.errOut, "profile:") {
				t.Errorf("%v must stop before resolving a profile: %q", args, r.errOut)
			}
		}
	})
}

// A value typed where a tag belongs (a connection string, a password) is refused on the client: it is never
// echoed, never sent, and never stored as a plaintext tag.
func TestValuesAreNotMistakenForTags(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p)
		const fake = "postgres://fakeuser:FAKEPW@db.example.test/app"
		for _, args := range [][]string{
			{"secret", "set", "DB_URL", fake, "--yes"},
			{"secret", "set", "DB_URL", "app:shop", fake, "--yes"},
			{"secret", "update", "DB_URL", "+" + fake},
			{"secret", "list", fake},
			{"secret", "get", "DB_URL", fake, "--reveal"},
			{"secret", "revoke", fake},
			{"run", fake, "--", "true"},
			{"workspace", "grant", "dev@example.test", "read", fake},
			{"workspace", "ungrant", "dev@example.test", fake},
		} {
			r := w.ku("v\n", false, nil, args...)
			if r.code != 1 || !strings.Contains(r.errOut, "is not a tag (key:value)") {
				t.Errorf("%v: %d %q", args, r.code, r.errOut)
			}
			noValue(t, r, fake, "FAKEPW", "fakeuser")
		}
		if r := mustOK(t, w.ku("", false, nil, "secret", "list")); r.out != "" || !strings.Contains(r.errOut, "No secrets found") {
			t.Fatalf("nothing may have been stored: %q %q", r.out, r.errOut)
		}
		if r := w.ku("v\n", false, nil, "secret", "set", "DB_URL", "app:shop", "x", "--yes"); !strings.Contains(r.errOut, "argument 3 is not a tag") {
			t.Fatalf("the message names the position: %q", r.errOut)
		}
	})
}

// The name goes into the query as data, so an & in it cannot add a parameter.
func TestListNameIsEscaped(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p)
		mustOK(t, w.ku("v\n", false, nil, "secret", "set", "DEMO_KEY", "app:shop", "--yes"))
		r := w.ku("", false, nil, "secret", "list", "DEMO_KEY&x=1")
		if r.code != 1 || !strings.Contains(r.errOut, "Invalid name") || strings.Contains(r.out, "DEMO_KEY") {
			t.Fatalf("an & in the name must reach the server whole, not select DEMO_KEY: %d %q %q", r.code, r.out, r.errOut)
		}
	})
}
