package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestAuditVerify(t *testing.T) {
	serverEnv(t)
	for _, e := range []string{"a", "b", "c"} {
		mustRun(t, "user", "invite", e+"@example.test")
	}
	p := openTest(t)
	var head []byte
	if err := p.DB().QueryRow(`SELECT hash FROM audit_log ORDER BY at DESC LIMIT 1`).Scan(&head); err != nil {
		t.Fatal(err)
	}
	out := mustRun(t, "audit", "verify")
	if want := fmt.Sprintf("OK: audit log verified, 3 rows, head %x", head); strings.TrimSpace(out) != want {
		t.Fatalf("got %q, want %q", out, want)
	}

	// an edit by someone with direct database access: the command fails
	if _, err := p.DB().Exec(`DROP TRIGGER audit_log_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.DB().Exec(`UPDATE audit_log SET action = 'login' WHERE rowid = (SELECT MIN(rowid) FROM audit_log)`); err != nil {
		t.Fatal(err)
	}
	out, err := runOut(t, "audit", "verify")
	if err == nil || !strings.Contains(err.Error(), "does not verify") || strings.Contains(out, "OK") {
		t.Fatalf("a tampered log must fail: %q %v", out, err)
	}
}
