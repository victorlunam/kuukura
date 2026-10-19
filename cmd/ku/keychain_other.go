//go:build !darwin

package main

import "errors"

type noKeychain struct{}

func newKeychain() tokenStore { return noKeychain{} }

var errNoKeychain = errors.New("the Keychain is only available on macOS. In CI set KU_URL and KU_TOKEN")

func (noKeychain) Get(string) (string, error) { return "", errNoToken }
func (noKeychain) Set(string, string) error   { return errNoKeychain }
func (noKeychain) Delete(string) error        { return nil }
