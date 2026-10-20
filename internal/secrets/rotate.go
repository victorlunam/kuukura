package secrets

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/keys"
)

// RewrapTx moves every DEK to the provider's active key without touching ciphertext, and records `key_rotate`
// for `by` in the caller's transaction: the audit row exists exactly when the rewrap committed. totp is how
// many TOTP secrets the auth service rewrapped in the same transaction; it only goes into the row. It returns
// how many versions were rewrapped.
func (s *Service) RewrapTx(ctx context.Context, tx *sql.Tx, by uuid.UUID, totp int) (int, error) {
	rows, err := tx.QueryContext(ctx, s.p.Rebind(`SELECT id, secret_id, number, ciphertext, nonce, wrapped_key, key_id, format_version
		FROM secret_versions WHERE key_id <> ?`), s.kp.KeyID())
	if err != nil {
		return 0, err
	}
	type item struct {
		id, secret uuid.UUID
		number     int
		pl         keys.Payload
	}
	var items []item
	for rows.Next() {
		var it item
		var fv int
		if err := rows.Scan(&it.id, &it.secret, &it.number, &it.pl.Ciphertext, &it.pl.Nonce, &it.pl.WrappedKey, &it.pl.KeyID, &fv); err != nil {
			_ = rows.Close()
			return 0, err
		}
		it.pl.FormatVersion = byte(fv) // #nosec G115 -- smallint column
		items = append(items, it)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	n := 0
	for _, it := range items {
		np, err := keys.Rewrap(ctx, s.kp, it.secret, uint32(it.number), it.pl) // #nosec G115 -- version numbers are small
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE secret_versions SET wrapped_key = ?, key_id = ? WHERE id = ?`), np.WrappedKey, np.KeyID, it.id); err != nil {
			return 0, err
		}
		n++
	}
	err = s.log.Append(ctx, tx, audit.Entry{Principal: by, Action: "key_rotate", TargetType: "key",
		Metadata: map[string]any{"key_id": s.kp.KeyID(), "secret_versions": n, "totp": totp}})
	return n, err
}

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
