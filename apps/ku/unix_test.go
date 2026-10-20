//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

// A link planted in the sessions folder that points outside of it is not followed.
func TestSessionStoreDoesNotFollowALinkOutOfTheFolder(t *testing.T) {
	s, _, dir := newTestStore(t, nil)
	if err := s.Set("home", "ku_tok"); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "other-token")
	if err := os.WriteFile(outside, []byte("ku_FAKE_OTHER"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "sessions", "work")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get("work"); err == nil || got != "" {
		t.Fatalf("a link out of the sessions folder must not be read: %q %v", got, err)
	}
}

// Ctrl-C reaches the command from the terminal, so ku does not send it a second one; a TERM is passed on.
func TestRunForwardsTermButNotInterrupt(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p)
		mustOK(t, w.ku("v\n", false, nil, "secret", "set", "DEMO_KEY", "app:shop", "--yes"))
		dir := t.TempDir()
		ready, log := filepath.Join(dir, "ready"), filepath.Join(dir, "log")
		script := `trap 'echo int >> "$1"' INT; trap 'echo term >> "$1"; exit 4' TERM; touch "$2"; while :; do sleep 0.05; done`

		go func() {
			for !fileExists(ready) {
				time.Sleep(10 * time.Millisecond)
			}
			self := os.Getpid()
			_ = syscall.Kill(self, syscall.SIGINT) // ku survives it; the command must not see it from ku
			time.Sleep(300 * time.Millisecond)
			_ = syscall.Kill(self, syscall.SIGTERM)
		}()
		r := w.ku("", false, nil, "run", "app:shop", "--", "sh", "-c", script, "sh", log, ready)
		b, _ := os.ReadFile(log)
		if r.code != 4 || strings.TrimSpace(string(b)) != "term" {
			t.Fatalf("exit %d, the command saw %q (want only term)\n%s", r.code, b, r.errOut)
		}
	})
}
