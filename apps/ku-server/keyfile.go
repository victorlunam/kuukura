package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/victorlunam/kuukura/internal/keys"
)

const showHint = "run `ku-server key show` once and store the key in your password manager"

// writeNew creates the file (and its directory, 0700) and fails if it exists.
func writeNew(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-chosen path
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// addKeyVersion appends a fresh key at the next version to the key file (write a sibling, then rename, keeping
// mode 0600) and returns the new body. errNotWritable means the key is not somewhere this command can change.
func addKeyVersion(path string) ([]byte, error) {
	old, err := os.ReadFile(path) // #nosec G304 -- operator-chosen path
	if err != nil {
		return nil, err
	}
	m, err := keys.ParseMasterKeys(old)
	if err != nil {
		return nil, err
	}
	next, err := keys.GenerateMasterKey(m.Version() + 1)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- operator-chosen path
	if err != nil {
		return nil, notWritable(err)
	}
	_ = f.Close()
	body := append(m.Ring(), next...)
	tmp := path + ".new"
	_ = os.Remove(tmp)
	if err := writeNew(tmp, body); err != nil {
		return nil, notWritable(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, notWritable(err)
	}
	return body, nil
}

var errNotWritable = errors.New("the key file is not writable")

func notWritable(err error) error {
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS) {
		return errNotWritable
	}
	return err
}

// addVersion appends the next version to the key file, or explains the manual path when the key is not in one.
func (a *app) addVersion() ([]byte, error) {
	if a.c.KeyFile != "" {
		body, err := addKeyVersion(a.c.KeyFile)
		if !errors.Is(err, errNotWritable) {
			return body, err
		}
	}
	next := 2
	if m, err := keys.ParseMasterKeys(a.c.MasterKey); err == nil {
		next = m.Version() + 1
	}
	return nil, fmt.Errorf("the master key is not in a writable key file, so it cannot add a version itself: add the line %d:<base64 of 32 random bytes, e.g. from `openssl rand -base64 32`> where the key lives, restart the server, then run `ku-server key rotate --rewrap-only`", next)
}
