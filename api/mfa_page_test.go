package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/auth"
)

// The second-step page offers only what the account really has. A passkey button for an account without one
// would just fail, so it is not rendered.
func TestMFAPageOffersOnlyRealMethods(t *testing.T) {
	renderDefault := func(passkey, totp bool, def string) string {
		s := &Server{Deps: Deps{BaseURL: "https://vault.example.com"}}
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(httptest.NewRequest("GET", "/auth/callback", nil), rec)
		if err := s.factorPage(c, auth.Pending{Token: "ku_x", Mode: "mfa", Methods: auth.Methods{Passkey: passkey, TOTP: totp, Default: def}}); err != nil {
			t.Fatal(err)
		}
		return rec.Body.String()
	}
	render := func(passkey, totp bool) string { return renderDefault(passkey, totp, "") }
	has := func(b, id string) bool { return strings.Contains(b, `id="`+id+`"`) }

	// the default factor's method comes first, and its button is the primary one
	passkeyFirst, totpFirst := renderDefault(true, true, "passkey"), renderDefault(true, true, "totp")
	if strings.Index(passkeyFirst, `id="pk"`) > strings.Index(passkeyFirst, `id="f-totp"`) || !strings.Contains(passkeyFirst, `class="btn primary" id="pk"`) {
		t.Fatal("default passkey: the passkey button comes first and is primary")
	}
	if strings.Index(totpFirst, `id="f-totp"`) > strings.Index(totpFirst, `id="pk"`) || !strings.Contains(totpFirst, `class="btn ghost" id="pk"`) || !strings.Contains(totpFirst, `class="btn primary" type="submit">Verify`) {
		t.Fatal("default authenticator app: the code form comes first and Verify is primary")
	}

	both := render(true, true)
	if !has(both, "pk") || !has(both, "f-totp") || !has(both, "f-rec") || !strings.Contains(both, `id="f-rec" autocomplete="off" hidden`) {
		t.Fatal("passkey + authenticator: passkey button, tabs, recovery behind its tab")
	}

	totpOnly := render(false, true)
	if has(totpOnly, "pk") || !has(totpOnly, "f-totp") || !strings.Contains(totpOnly, "Enter the code from your authenticator app") {
		t.Fatal("authenticator only: no passkey button, the code form is the main way in")
	}
	if !strings.Contains(totpOnly, `class="btn primary" type="submit">Verify`) {
		t.Fatal("authenticator only: Verify is the primary button, as on the confirmation page")
	}

	passkeyOnly := render(true, false)
	if !has(passkeyOnly, "pk") || has(passkeyOnly, "f-totp") || has(passkeyOnly, "tab-totp") {
		t.Fatal("passkey only: no authenticator form or tab")
	}
	if !has(passkeyOnly, "f-rec") || strings.Contains(passkeyOnly, `id="f-rec" autocomplete="off" hidden`) {
		t.Fatal("passkey only: the recovery code form is available and visible")
	}

	recoveryOnly := render(false, false)
	if has(recoveryOnly, "pk") || has(recoveryOnly, "f-totp") || !has(recoveryOnly, "f-rec") || !strings.Contains(recoveryOnly, "recovery codes") {
		t.Fatal("no usable factor: only recovery codes")
	}
}
