package authtest

import (
	"context"
	"errors"
	"sync"

	"github.com/victorlunam/kuukura/internal/auth"
)

// IDP is a fake login provider: a sign-in code the test registered answers with the identity it was given.
type IDP struct {
	mu     sync.Mutex
	byCode map[string]auth.Identity
}

func NewIDP() *IDP { return &IDP{byCode: map[string]auth.Identity{}} }

// Allow makes code sign in as id.
func (f *IDP) Allow(code string, id auth.Identity) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byCode[code] = id
}

func (f *IDP) Name() string { return "google" }
func (f *IDP) AuthURL(state, nonce, verifier string) string {
	return "https://idp.test/?state=" + state
}
func (f *IDP) Exchange(_ context.Context, code, _, _ string) (auth.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.byCode[code]
	if !ok {
		return auth.Identity{}, errors.New("bad code")
	}
	return id, nil
}
