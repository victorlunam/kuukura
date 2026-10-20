package main

import (
	"errors"
	"testing"
)

// The platform's real keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) stores, reads
// and deletes a token. On a Linux machine without a keyring (CI, containers) it must fail cleanly so that the
// session store falls back to a file; that case is checked through the session store.
func TestSystemStoreAndFallback(t *testing.T) {
	const profile = "zz-test-system-store"
	system := newSystemStore()
	t.Cleanup(func() { _ = system.Delete(profile) })

	s, warnings, dir := newTestStore(t, system)
	if err := s.Set(profile, "ku_FAKE_TOKEN"); err != nil {
		t.Fatalf("saving a session must work on every OS, with a keychain or with the file fallback: %v", err)
	}
	if got, err := s.Get(profile); err != nil || got != "ku_FAKE_TOKEN" {
		t.Fatalf("get after set: %q %v", got, err)
	}
	// wherever it went, exactly one place holds it, and a warning says so when it is the file
	onDisk := fileExists(dir + "/sessions/" + profile)
	if onDisk != (len(*warnings) == 1) {
		t.Fatalf("a file copy and the warning go together: file=%v warnings=%v", onDisk, *warnings)
	}
	if err := s.Delete(profile); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(profile); !errors.Is(err, errNoToken) {
		t.Fatalf("after delete: %v", err)
	}
}
