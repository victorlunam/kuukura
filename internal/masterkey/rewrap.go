// Package masterkey is what spans every table encrypted under the master key: rotation, the start-up check and
// the "shown once" rule. It sits above secrets and auth so neither needs to know about the other.
package masterkey

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/auth"
	"github.com/victorlunam/kuukura/internal/secrets"
	"github.com/victorlunam/kuukura/internal/storage"
)

// Rewrap moves every secret DEK and every TOTP secret to the services' active key in one transaction, together
// with the `key_rotate` audit row for `by`: the row exists exactly when the rewrap committed. It returns how many
// secret versions and TOTP secrets were rewrapped.
func Rewrap(ctx context.Context, p storage.Provider, sec *secrets.Service, authSvc *auth.Service, by uuid.UUID) (nSecrets, nTOTP int, err error) {
	err = storage.InTx(ctx, p, func(tx *sql.Tx) (err error) {
		if nTOTP, err = authSvc.RewrapTOTPTx(ctx, tx); err != nil {
			return err
		}
		nSecrets, err = sec.RewrapTx(ctx, tx, by, nTOTP)
		return err
	})
	return nSecrets, nTOTP, err
}
