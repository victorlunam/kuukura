package main

import "errors"

// tokenStore keeps one session token per profile. The real one is the macOS Keychain.
type tokenStore interface {
	Get(profile string) (string, error)
	Set(profile, token string) error
	Delete(profile string) error
}

var errNoToken = errors.New("no token")
