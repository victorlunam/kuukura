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
	entries, _ := os.ReadDir(filepath.Dir(dir)) // nothing may appear next to the config folder
	for _, e := range entries {
		if e.Name() == "escape" {
			t.Fatal("a path was written outside the sessions folder")
		}
	}
}

func TestConfigRootPerOS(t *testing.T) {
	cases := []struct{ goos, home, xdg, appData, want string }{
		{"darwin", "/Users/a", "", "", "/Users/a/.config"},
		{"linux", "/home/a", "", "", "/home/a/.config"},
		{"linux", "/home/a", "/custom", "", "/custom"},
		{"darwin", "/Users/a", "/custom", "", "/custom"},
		{"linux", "/home/a", "relative", "", "/home/a/.config"}, // a relative XDG_CONFIG_HOME is ignored
		{"windows", `C:\Users\a`, "", `C:\Users\a\AppData\Roaming`, `C:\Users\a\AppData\Roaming`},
	}
	for _, c := range cases {
		if got := configRoot(c.goos, c.home, c.xdg, c.appData); filepath.ToSlash(got) != filepath.ToSlash(c.want) {
			t.Errorf("%+v: got %q want %q", c, got, c.want)
		}
	}
	// on Windows without APPDATA it still has a place to go
	if got := configRoot("windows", "/home/a", "", ""); filepath.ToSlash(got) != "/home/a/.config" {
		t.Errorf("windows without APPDATA: %q", got)
	}
}

func TestOpenCommandPerOS(t *testing.T) {
	u := "http://localhost:8080/auth/login?cli_port=1&cli_state=s"
	for goos, want := range map[string][]string{
		"darwin":  {"open", u},
		"linux":   {"xdg-open", u},
		"windows": {"rundll32", "url.dll,FileProtocolHandler", u},
	} {
		name, args := openCommand(goos, u)
		got := append([]string{name}, args...)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s: got %v want %v", goos, got, want)
		}
	}
	// the URL is always one argument (the & of a query string must never reach a shell)
	if _, args := openCommand("windows", u); args[len(args)-1] != u {
		t.Error("the URL must stay a single argument")
	}
}
