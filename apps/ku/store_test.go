package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeSystem stands in for a keychain: it can be made to fail like a machine that has none.
type fakeSystem struct {
	m    map[string]string
	fail bool
}

func (f *fakeSystem) Get(p string) (string, error) {
	if f.fail {
		return "", errors.New("no keychain here")
	}
	if t, ok := f.m[p]; ok {
		return t, nil
	}
	return "", errNoToken
}
func (f *fakeSystem) Set(p, t string) error {
	if f.fail {
		return errors.New("no keychain here")
	}
	f.m[p] = t
	return nil
}
func (f *fakeSystem) Delete(p string) error { delete(f.m, p); return nil }

func newTestStore(t *testing.T, system tokenStore) (*sessionStore, *[]string, string) {
	dir := t.TempDir()
	var warnings []string
	return newSessionStore(system, dir, func(m string) { warnings = append(warnings, m) }), &warnings, dir
}

func TestSessionStoreUsesTheKeychainWhenThereIsOne(t *testing.T) {
	sys := &fakeSystem{m: map[string]string{}}
	s, warnings, dir := newTestStore(t, sys)
	if err := s.Set("work", "ku_tok"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get("work"); err != nil || got != "ku_tok" {
		t.Fatalf("get: %q %v", got, err)
	}
	if sys.m["work"] != "ku_tok" {
		t.Fatal("the token must be in the keychain")
	}
	if _, err := os.Stat(filepath.Join(dir, "sessions", "work")); err == nil {
		t.Fatal("with a keychain nothing is written to disk")
	}
	if len(*warnings) != 0 {
		t.Fatalf("no warning when the keychain works: %v", *warnings)
	}
	if err := s.Delete("work"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("work"); !errors.Is(err, errNoToken) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestSessionStoreFallsBackToAPrivateFile(t *testing.T) {
	for name, sys := range map[string]tokenStore{
		"keychain fails": &fakeSystem{m: map[string]string{}, fail: true},
		"no keychain":    nil,
	} {
		t.Run(name, func(t *testing.T) {
			s, warnings, dir := newTestStore(t, sys)
			if err := s.Set("work", "ku_tok"); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "sessions", "work")
			b, err := os.ReadFile(path)
			if err != nil || string(b) != "ku_tok" {
				t.Fatalf("file: %q %v", b, err)
			}
			if runtime.GOOS != "windows" { // Windows has no Unix modes: the profile folder's ACL applies
				if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
					t.Fatalf("session file mode %v, want 0600", st.Mode().Perm())
				}
				if st, _ := os.Stat(filepath.Dir(path)); st.Mode().Perm() != 0o700 {
					t.Fatalf("sessions folder mode %v, want 0700", st.Mode().Perm())
				}
			}
			if got, err := s.Get("work"); err != nil || got != "ku_tok" {
				t.Fatalf("get: %q %v", got, err)
			}
			// one warning per run, and it names the file
			_ = s.Set("work", "ku_tok2")
			if len(*warnings) != 1 || !strings.Contains((*warnings)[0], path) || !strings.Contains((*warnings)[0], "not encrypted") {
				t.Fatalf("expected one warning naming the file: %v", *warnings)
			}
			if err := s.Delete("work"); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); err == nil {
				t.Fatal("delete removes the file")
			}
			if _, err := s.Get("work"); !errors.Is(err, errNoToken) {
				t.Fatalf("no token: %v", err)
			}
		})
	}
}

func TestSessionStoreNeverKeepsTwoCopies(t *testing.T) {
	sys := &fakeSystem{m: map[string]string{}, fail: true}
	s, _, dir := newTestStore(t, sys)
	if err := s.Set("work", "old"); err != nil { // saved to the file while the keychain was down
		t.Fatal(err)
	}
	sys.fail = false // the keychain is back
	if err := s.Set("work", "new"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sessions", "work")); err == nil {
		t.Fatal("the stale file copy must be removed once the keychain holds the token")
	}
	if got, _ := s.Get("work"); got != "new" {
		t.Fatalf("got %q", got)
	}
	// deleting clears both places
	sys.fail = true
	_ = s.Set("home", "x")
	sys.fail = false
	sys.m["home"] = "y"
	if err := s.Delete("home"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("home"); !errors.Is(err, errNoToken) {
		t.Fatal("delete must clear the keychain and the file")
	}
}

func TestSessionStoreRefusesAFileOtherUsersCanRead(t *testing.T) {
	s, _, dir := newTestStore(t, nil)
	if err := s.Set("work", "ku_tok"); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return // no Unix modes to check; the ACL of the user's profile folder protects the file
	}
	path := filepath.Join(dir, "sessions", "work")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := s.Get("work")
	if err == nil || !strings.Contains(err.Error(), "chmod 600") || strings.Contains(err.Error(), "ku_tok") {
		t.Fatalf("a world-readable session file must be refused, without leaking it: %v", err)
	}
}

func TestSessionStoreRejectsUnsafeProfileNames(t *testing.T) {
	s, _, dir := newTestStore(t, nil)
	for _, bad := range []string{"../escape", "a/b", `a\b`, "", ".", "..", "UPPER", strings.Repeat("a", 40), "a b"} {
		if err := s.Set(bad, "tok"); err == nil {
			t.Fatalf("profile %q must be rejected", bad)
		}
		if _, err := s.Get(bad); err == nil {
			t.Fatalf("get %q must be rejected", bad)
		}
		if err := s.Delete(bad); err == nil {
			t.Fatalf("delete %q must be rejected", bad)
		}
	}
	// "../escape" would land in <dir>/escape, next to the sessions folder
	if fileExists(filepath.Join(dir, "escape")) || fileExists(filepath.Join(dir, "sessions", "escape")) {
		t.Fatal("a path was written outside the sessions folder")
	}
}

// The folder is opened as a root, so even a name that passes the check cannot reach outside it.
func TestSessionStoreFileNamesStayInsideTheFolder(t *testing.T) {
	s, _, dir := newTestStore(t, nil)
	if err := s.Set("work", "ku_tok"); err != nil {
		t.Fatal(err)
	}
	root, err := s.root()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if f, err := root.OpenFile("../escape", os.O_WRONLY|os.O_CREATE, 0o600); err == nil || fileExists(filepath.Join(dir, "escape")) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("a name with .. must not resolve outside the sessions folder: %v", err)
	}
}

// A keychain that took an older token and then fails (locked, removed) must not keep answering with it once the
// newer token went to the file.
func TestSessionStoreFallbackDropsTheOlderKeychainToken(t *testing.T) {
	sys := &fakeSystem{m: map[string]string{}}
	s, _, dir := newTestStore(t, sys)
	if err := s.Set("work", "old"); err != nil {
		t.Fatal(err)
	}
	if sys.m["work"] != "old" {
		t.Fatal("setup: the first token is in the keychain")
	}
	sys.fail = true
	if err := s.Set("work", "new"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "sessions", "work")); string(b) != "new" {
		t.Fatalf("the file holds the new token: %q", b)
	}
	if _, ok := sys.m["work"]; ok {
		t.Fatal("the older keychain entry must be deleted when the token falls back to the file")
	}
	sys.fail = false // the keychain works again and is read first
	if got, err := s.Get("work"); err != nil || got != "new" {
		t.Fatalf("get after the fallback: %q %v", got, err)
	}
}
