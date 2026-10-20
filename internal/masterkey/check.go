package masterkey

import (
	"context"
	"errors"

	"github.com/victorlunam/kuukura/internal/auth"
	"github.com/victorlunam/kuukura/internal/secrets"
)

// HasEncryptedData reports whether the database holds anything encrypted under the master key. A key generated
// over such data would lock it forever.
func HasEncryptedData(ctx context.Context, sec *secrets.Service, authSvc *auth.Service) (bool, error) {
	hasVersions, err := sec.HasVersions(ctx)
	if err != nil {
		return false, err
	}
	hasTOTP, err := authSvc.HasTOTP(ctx)
	return hasVersions || hasTOTP, err
}

// Check opens one stored secret and one stored TOTP secret with the master key, so a wrong key is found at
// start instead of at the first read.
func Check(ctx context.Context, sec *secrets.Service, authSvc *auth.Service) error {
	return errors.Join(sec.CheckKey(ctx), authSvc.CheckKey(ctx))
}
