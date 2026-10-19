package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// tokenStore keeps one session token per profile.
type tokenStore interface {
	Get(profile string) (string, error)
	Set(profile, token string) error
	Delete(profile string) error
}

var errNoToken = errors.New("no token")

// sessionStore keeps the session as safely as the system allows:
//
//  1. the system keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service);
//  2. only if there is none (a server, a container, WSL): a private file, readable only by you.
//
// The token is never in both places, and never in config.toml. Sessions are short (8 h, 1 h idle) and the server
// revokes them on demand, which bounds what a copy of the file is worth.
type sessionStore struct {
	system tokenStore // nil when the platform has no keychain
	dir    string     // where fallback files live: <config dir>/sessions
	warn   func(string)

	once sync.Once
}

func newSessionStore(system tokenStore, configDir string, warn func(string)) *sessionStore {
	return &sessionStore{system: system, dir: filepath.Join(configDir, "sessions"), warn: warn}
}

// profile names are validated when a profile is added; this is the last line of defence for the file path.
func (s *sessionStore) path(profile string) (string, error) {
	if !profileRE.MatchString(profile) {
		return "", fmt.Errorf("invalid profile name")
	}
	return filepath.Join(s.dir, profile), nil
}

func (s *sessionStore) Set(profile, token string) error {
	path, err := s.path(profile)
	if err != nil {
		return err
	}
	if s.system != nil {
		if err := s.system.Set(profile, token); err == nil {
			_ = os.Remove(path) // a stale fallback copy would be a second place for the token
			return nil
		}
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	if err := writePrivate(path, []byte(token)); err != nil {
		return err
	}
	s.once.Do(func() {
		s.warn("No system keychain is available here, so the session was saved in a private file:\n  " + path +
			"\nOnly your user can read it, but it is not encrypted. It expires in 8 hours.")
	})
	return nil
}

func (s *sessionStore) Get(profile string) (string, error) {
	path, err := s.path(profile)
	if err != nil {
		return "", err
	}
	if s.system != nil {
		if tok, err := s.system.Get(profile); err == nil && tok != "" {
			return tok, nil
		}
	}
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", errNoToken
	}
	if err != nil {
		return "", err
	}
	// Refuse a session file other users can read (Windows has no Unix modes: the profile folder's ACL applies).
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s can be read by other users. Run: chmod 600 %s, then log in again with: ku login", path, path)
	}
	b, err := os.ReadFile(path) // #nosec G304 -- fixed folder, validated profile name
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", errNoToken
	}
	return string(b), nil
}

func (s *sessionStore) Delete(profile string) error {
	path, err := s.path(profile)
	if err != nil {
		return err
	}
	var first error
	// Only touch the keychain if the token is really there. Where there is no keychain every call fails, and
	// that is not an error for "delete".
	if s.system != nil {
		if tok, err := s.system.Get(profile); err == nil && tok != "" {
			first = s.system.Delete(profile)
		}
	}
	// #nosec G703 -- path is <config>/sessions/<profile>, and the profile name was validated by path()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
		first = err
	}
	return first
}
