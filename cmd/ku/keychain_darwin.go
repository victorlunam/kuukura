//go:build darwin

package main

import (
	"github.com/keybase/go-keychain"
)

// One generic-password item per profile, readable only while unlocked and never synced or migrated
// to another device. Tokens are never written to config files.
type keychainStore struct{}

func newKeychain() tokenStore { return keychainStore{} }

const keychainService = "kuukura"

func (keychainStore) Get(profile string) (string, error) {
	b, err := keychain.GetGenericPassword(keychainService, profile, "", "")
	if err != nil {
		return "", err
	}
	if b == nil {
		return "", errNoToken
	}
	return string(b), nil
}

func (k keychainStore) Set(profile, token string) error {
	_ = k.Delete(profile)
	it := keychain.NewItem()
	it.SetSecClass(keychain.SecClassGenericPassword)
	it.SetService(keychainService)
	it.SetAccount(profile)
	it.SetLabel("kuukura (" + profile + ")")
	it.SetData([]byte(token))
	it.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)
	it.SetSynchronizable(keychain.SynchronizableNo)
	return keychain.AddItem(it)
}

func (keychainStore) Delete(profile string) error {
	err := keychain.DeleteGenericPasswordItem(keychainService, profile)
	if err == keychain.ErrorItemNotFound {
		return nil
	}
	return err
}
