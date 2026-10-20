package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/cli"
)

func runOut(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return capture(t, func() error { return run(args) })
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := runOut(t, args...)
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return out
}

func TestCommandTree(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"--help"}, {"-h"}} {
		out, err := runOut(t, args...)
		if err != nil || out != helpText {
			t.Fatalf("%v: %q %v", args, out, err)
		}
	}
	// every command of the tree is in the help, one "noun verb" line each, and the description column is aligned
	col := -1
	for l := range strings.SplitSeq(helpText, "\n") {
		if !strings.HasPrefix(l, "  ") {
			continue
		}
		i := strings.Index(l[2:], "  ") + 2
		j := i + len(l[i:]) - len(strings.TrimLeft(l[i:], " "))
		if col == -1 {
			col = j
		}
		if i < 2 || j != col {
			t.Errorf("description of %q starts at column %d, not %d", l, j, col)
		}
	}
	for _, c := range []string{"serve", "healthcheck", "version", "key init", "key rotate", "key show", "user list", "user invite",
		"user disable", "user enable", "user reset-factors", "audit verify"} {
		if !strings.Contains(helpText, "\n  "+c) {
			t.Errorf("%q is not in the help", c)
		}
	}
	if err := run(nil); !errors.Is(err, errUnknown) {
		t.Errorf("no command: %v", err)
	}
	if err := run([]string{"nope"}); !errors.Is(err, errUnknown) || strings.Contains(err.Error(), "nope") {
		t.Errorf("an unknown command is not echoed: %v", err)
	}
	var u cli.UsageError
	if err := run([]string{"user", "invite"}); !errors.As(err, &u) || u != "ku-server user invite <email> [--admin]" {
		t.Errorf("each command prints its own usage line: %v", err)
	}
	if out := mustRun(t, "version"); strings.TrimSpace(out) != version {
		t.Fatal(out)
	}
	for _, args := range [][]string{
		{"admin", "invite"}, {"init"}, {"key"}, {"key", "nope"}, {"user"}, {"user", "invite"}, {"user", "invite", "a@example.test", "b@example.test"},
		{"user", "invite", "a@example.test", "--bogus"}, {"user", "list", "extra"}, {"user", "disable"}, {"audit", "verify", "extra"},
		{"key", "show", "extra"}, {"key", "rotate", "extra"}, {"key", "init", "--nope"}, {"serve", "extra"},
	} {
		if out, err := runOut(t, args...); err == nil || out != "" || strings.Contains(err.Error(), "\n") {
			t.Errorf("%v: one plain error line and no data, got %q %v", args, out, err)
		}
	}
}

// Exit 0 on success, 1 when a command ran and failed, 2 when the arguments were wrong (`ku` does the same).
func TestExitCodes(t *testing.T) {
	for err, want := range map[error]int{
		nil:                             0,
		errors.New("it broke"):          cli.ExitFail,
		cli.UsageError("ku-server x"):   cli.ExitUsage,
		fmt.Errorf("x: %w", errUnknown): cli.ExitUsage,
	} {
		if got := report(err); got != want {
			t.Errorf("%v: exit %d, want %d", err, got, want)
		}
	}
}
