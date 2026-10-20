package auth_test

import (
	"slices"
	"testing"

	"github.com/victorlunam/kuukura/auth"
)

// The default kind comes first: the CLI and the pages offer the first one.
func TestMethodsKinds(t *testing.T) {
	for _, c := range []struct {
		m    auth.Methods
		want []string
	}{
		{auth.Methods{Passkey: true}, []string{"passkey"}},
		{auth.Methods{TOTP: true, Default: "totp"}, []string{"totp"}},
		{auth.Methods{Passkey: true, TOTP: true, Default: "passkey"}, []string{"passkey", "totp"}},
		{auth.Methods{Passkey: true, TOTP: true, Default: "totp"}, []string{"totp", "passkey"}},
	} {
		if got := c.m.Kinds(); !slices.Equal(got, c.want) {
			t.Errorf("%+v: %v, want %v", c.m, got, c.want)
		}
	}
	if !auth.ValidPurpose(auth.PurposeReveal) || auth.ValidPurpose("delete_everything") {
		t.Error("ValidPurpose")
	}
}
