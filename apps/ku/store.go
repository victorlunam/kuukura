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

// check validates a profile name, which is also a file name. Profile names are validated when a profile is added;
// this and the os.Root every file access goes through are the last lines of defence against a path.
func (s *sessionStore) check(profile string) error {
	if !profileRE.MatchString(profile) {
		return errors.New("invalid profile name")
	}
	return nil
}

// root opens the sessions folder; nothing inside it can name a file outside of it.
func (s *sessionStore) root() (*os.Root, error) { return os.OpenRoot(s.dir) }

func (s *sessionStore) Set(profile, token string) error {
	if err := s.check(profile); err != nil {
		return err
	}
	if s.system != nil {
		if err := s.system.Set(profile, token); err == nil {
			_ = s.removeFile(profile) // a stale fallback copy would be a second place for the token
			return nil
		}
		_ = s.system.Delete(profile) // and an older keychain entry would be read before the file
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	root, err := s.root()
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(profile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := fillPrivate(f, []byte(token)); err != nil {
		return err
	}
	s.once.Do(func() {
		s.warn("No system keychain is available here, so the session was saved in a private file:\n  " + filepath.Join(s.dir, profile) +
			"\nOnly your user can read it, but it is not encrypted. It expires in 8 hours.")
	})
	return nil
}

func (s *sessionStore) Get(profile string) (string, error) {
	if err := s.check(profile); err != nil {
		return "", err
	}
	if s.system != nil {
		if tok, err := s.system.Get(profile); err == nil && tok != "" {
			return tok, nil
		}
	}
	root, err := s.root()
	if errors.Is(err, os.ErrNotExist) {
		return "", errNoToken
	}
	if err != nil {
		return "", err
	}
	defer root.Close()
	st, err := root.Stat(profile)
	if errors.Is(err, os.ErrNotExist) {
		return "", errNoToken
	}
	if err != nil {
		return "", err
	}
	// Refuse a session file other users can read (Windows has no Unix modes: the profile folder's ACL applies).
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		path := filepath.Join(s.dir, profile)
		return "", fmt.Errorf("%s can be read by other users. Run: chmod 600 %s, then log in again with: ku login", path, path)
	}
	b, err := root.ReadFile(profile)
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", errNoToken
	}
	return string(b), nil
}

func (s *sessionStore) Delete(profile string) error {
	if err := s.check(profile); err != nil {
		return err
	}
	var keychain error
	// Only touch the keychain if the token is really there. Where there is no keychain every call fails, and
	// that is not an error for "delete".
	if s.system != nil {
		if tok, err := s.system.Get(profile); err == nil && tok != "" {
			keychain = s.system.Delete(profile)
		}
	}
	return errors.Join(keychain, s.removeFile(profile))
}

// removeFile deletes the fallback file; a missing file or folder is fine.
func (s *sessionStore) removeFile(profile string) error {
	root, err := s.root()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Remove(profile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
