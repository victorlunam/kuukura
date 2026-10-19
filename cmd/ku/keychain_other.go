//go:build !darwin

package main

import (
	"errors"

	"github.com/zalando/go-keyring"
)

// The system keychain on Windows (Credential Manager) and Linux (Secret Service: GNOME Keyring, KWallet).
// Pure Go, no cgo. Where there is none (a headless server, a container), Set/Get return an error and the
// sessionStore falls back to a private file.
type keyringStore struct{}

func newSystemStore() tokenStore { return keyringStore{} }

const keyringService = "kuukura"

func (keyringStore) Get(profile string) (string, error) {
	tok, err := keyring.Get(keyringService, profile)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", errNoToken
	}
	return tok, err
}

func (keyringStore) Set(profile, token string) error {
	return keyring.Set(keyringService, profile, token)
}

func (keyringStore) Delete(profile string) error {
	err := keyring.Delete(keyringService, profile)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}
