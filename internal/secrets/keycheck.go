package secrets

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/keys"
)

// HasVersions reports whether any secret version (encrypted under the master key) is stored.
func (s *Service) HasVersions(ctx context.Context) (bool, error) {
	var n int
	err := s.p.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM secret_versions`).Scan(&n)
	return n > 0, err
}

// CheckKey opens the DEK of one stored version with the master key, so a wrong key is found at start instead of
// at the first read. It passes when there is none.
func (s *Service) CheckKey(ctx context.Context) error {
	var it struct {
		secret uuid.UUID
		number int
		pl     keys.Payload
	}
	var fv int
	err := s.p.DB().QueryRowContext(ctx, `SELECT secret_id, number, wrapped_key, key_id, format_version FROM secret_versions LIMIT 1`).
		Scan(&it.secret, &it.number, &it.pl.WrappedKey, &it.pl.KeyID, &fv)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	it.pl.FormatVersion = byte(fv)                                                         // #nosec G115 -- smallint column
	if _, err := keys.Rewrap(ctx, s.kp, it.secret, uint32(it.number), it.pl); err != nil { // #nosec G115 -- version numbers are small
		if errors.Is(err, keys.ErrDecrypt) {
			return keys.MismatchError(it.pl.KeyID)
		}
		return err
	}
	return nil
}
