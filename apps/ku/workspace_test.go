package main

import (
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

func TestWorkspaceCommands(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w := newWorld(t, p)
		admin := w.admin()
		w.loginAs(admin)
		r := mustOK(t, w.ku("", false, nil, "workspace", "invite", "new@example.test"))
		if !strings.Contains(r.out, w.srv.URL+"/invite?token=ku_") || !strings.Contains(r.errOut, "✓ Invited new@example.test") {
			t.Fatalf("invite: %q", r.out)
		}
		if !strings.Contains(r.out, "&profile=default") {
			t.Fatalf("the invite link suggests the inviter's profile name: %q", r.out)
		}
		w.member(admin, "dev@example.test")
		long := "a-very-long-person-name.with.dots@a-long-subdomain.example.test" // longer than any fixed column
		w.member(admin, long)
		mustOK(t, w.ku("", false, nil, "workspace", "group", "pay", "+dev@example.test"))
		mustOK(t, w.ku("", false, nil, "workspace", "grant", "pay", "write", "team:pay"))
		mustOK(t, w.ku("", false, nil, "workspace", "ungrant", "pay", "team:pay"))
		mustOK(t, w.ku("", false, nil, "workspace", "group", "pay", "-dev@example.test"))
		r = mustOK(t, w.ku("", false, nil, "workspace", "audit"))
		if !strings.Contains(r.out, "WHEN (UTC)") || !strings.Contains(r.out, "group_add") || !strings.Contains(r.out, "grant") {
			t.Fatalf("audit: %q", r.out)
		}
		// columns follow the content: a long email must be followed by at least two spaces, never glued to the action
		sawLong := false
		for l := range strings.SplitSeq(strings.TrimSpace(r.out), "\n") {
			if i := strings.Index(l, long); i >= 0 {
				sawLong = true
				if !strings.HasPrefix(l[i+len(long):], "  ") {
					t.Fatalf("columns run together: %q", l)
				}
			}
		}
		if !sawLong {
			t.Fatalf("the long-named person has audit rows: %q", r.out)
		}
		if r := w.ku("", false, nil, "workspace", "disable", "root@example.test"); r.code != 1 || !strings.Contains(r.errOut, "last admin") {
			t.Fatalf("last admin: %q", r.errOut)
		}
		if r := w.ku("", false, nil, "workspace", "enable", "dev@example.test"); r.code != 1 || !strings.Contains(r.errOut, "not disabled") {
			t.Fatalf("enable an active person: %q", r.errOut)
		}
		r = mustOK(t, w.ku("", false, nil, "workspace", "disable", "dev@example.test"))
		if !strings.Contains(r.errOut, "✓ Disabled dev@example.test") {
			t.Fatalf("disable: %q", r.errOut)
		}
		r = mustOK(t, w.ku("", false, nil, "workspace", "enable", "dev@example.test"))
		if !strings.Contains(r.errOut, "✓ Enabled dev@example.test") {
			t.Fatalf("enable: %q", r.errOut)
		}
		mustOK(t, w.ku("", false, nil, "workspace", "disable", "dev@example.test"))
		// a member cannot use admin commands
		dev2 := w.member(admin, "dev2@example.test")
		_ = w.store.Set("default", dev2)
		if r := w.ku("", false, nil, "workspace", "audit"); r.code != 1 || !strings.Contains(r.errOut, "don't have access") {
			t.Fatalf("member audit: %q", r.errOut)
		}
	})
}
