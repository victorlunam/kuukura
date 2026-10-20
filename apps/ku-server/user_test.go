package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/audit"
)

func TestUserCommands(t *testing.T) {
	serverEnv(t)
	link := regexp.MustCompile(`valid until \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\):\nhttps://vault.example.test/invite\?token=ku_\S+\n`)
	out := mustRun(t, "user", "invite", "Root@Example.test", "--admin")
	if !link.MatchString(out) {
		t.Fatalf("a link with an RFC 3339 UTC expiry: %q", out)
	}
	mustRun(t, "user", "invite", "--admin", "other@example.test")
	if out := mustRun(t, "user", "invite", "dev@example.test"); !link.MatchString(out) {
		t.Fatalf("%q", out)
	}
	p := openTest(t)
	var n int
	if err := p.DB().QueryRow(`SELECT COUNT(*) FROM principals WHERE (name = 'root@example.test' AND role = 'admin') OR (name = 'dev@example.test' AND role = 'member')`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("admin with --admin, member without: %d %v", n, err)
	}
	if _, err := runOut(t, "user", "invite", "root@example.test"); err == nil {
		t.Fatal("the role must match a pending invite")
	}

	// two people active, with one passkey for the member
	if _, err := p.DB().Exec(`UPDATE principals SET status = 'active' WHERE name IN ('root@example.test', 'dev@example.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.DB().Exec(p.Rebind(`INSERT INTO credentials (id, principal_id, kind, public_key) VALUES (?, (SELECT id FROM principals WHERE name = 'dev@example.test'), 'passkey', ?)`), uuid.New(), []byte{1}); err != nil {
		t.Fatal(err)
	}
	out = mustRun(t, "user", "list")
	if strings.Contains(out, "ku-server") || !regexp.MustCompile(`(?m)^dev@example.test\s+human\s+member\s+active\s+1\s+\d{4}-\d\d-\d\d$`).MatchString(out) ||
		!regexp.MustCompile(`(?m)^root@example.test\s+human\s+admin\s+active\s+0\s`).MatchString(out) || !strings.Contains(out, "other@example.test") ||
		strings.Contains(out, "ku_") {
		t.Fatalf("name, kind, role, status, factors, date; no host principal, no tokens:\n%s", out)
	}

	if _, err := runOut(t, "user", "disable", "root@example.test"); err == nil {
		t.Fatal("the last active admin cannot be disabled")
	}
	if out := mustRun(t, "user", "disable", "dev@example.test"); !strings.Contains(out, "Disabled dev@example.test") {
		t.Fatal(out)
	}
	if out := mustRun(t, "user", "list"); !regexp.MustCompile(`dev@example.test\s+human\s+member\s+disabled`).MatchString(out) {
		t.Fatal(out)
	}
	if out := mustRun(t, "user", "enable", "dev@example.test"); !strings.Contains(out, "Enabled dev@example.test (active)") {
		t.Fatal(out)
	}
	if _, err := runOut(t, "user", "enable", "ku-server"); err == nil {
		t.Fatal("the host principal is not manageable")
	}

	// reset-factors: the passkey is gone, the person is back in enrollment, and a link is printed
	out = mustRun(t, "user", "reset-factors", "dev@example.test")
	if !link.MatchString(out) {
		t.Fatalf("%q", out)
	}
	if out := mustRun(t, "user", "list"); !regexp.MustCompile(`dev@example.test\s+human\s+member\s+invited\s+0\s`).MatchString(out) {
		t.Fatal(out)
	}
	if _, err := runOut(t, "user", "reset-factors", "dev@example.test"); err == nil {
		t.Fatal("nothing left to reset")
	}

	// every change is audited under the host principal, and no link is in the log
	rows, err := audit.New(p).List(t.Context(), audit.Filter{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 6 {
		t.Fatalf("3 invites, disable, enable, reset (the refused ones leave nothing): %d", len(rows))
	}
	for _, r := range rows {
		if r.PrincipalName != "ku-server" {
			t.Fatalf("audited under %q: %+v", r.PrincipalName, r)
		}
		for _, v := range r.Metadata {
			if s, _ := v.(string); strings.Contains(s, "ku_") {
				t.Fatal("a link in the audit log")
			}
		}
	}
	if err := audit.New(p).Verify(t.Context()); err != nil {
		t.Fatal(err)
	}
}
