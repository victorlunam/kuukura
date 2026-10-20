package secrets

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/keys"
	"github.com/victorlunam/kuukura/storage"
)

// RewrapAll moves every DEK to the provider's active key without touching ciphertext, and records `key_rotate`
// for admin `by` in the same transaction: the audit row exists exactly when the rewrap committed. totp is how
// many TOTP secrets the auth service rewrapped just before; it only goes into the row. It returns how many
// versions were rewrapped.
func (s *Service) RewrapAll(ctx context.Context, by uuid.UUID, totp int) (int, error) {
	n := 0
	err := storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, s.p.Rebind(`SELECT id, secret_id, number, ciphertext, nonce, wrapped_key, key_id, format_version
			FROM secret_versions WHERE key_id <> ?`), s.kp.KeyID())
		if err != nil {
			return err
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
				return err
			}
			it.pl.FormatVersion = byte(fv) // #nosec G115 -- smallint column
			items = append(items, it)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, it := range items {
			np, err := keys.Rewrap(ctx, s.kp, it.secret, uint32(it.number), it.pl) // #nosec G115 -- version numbers are small
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE secret_versions SET wrapped_key = ?, key_id = ? WHERE id = ?`), np.WrappedKey, np.KeyID, it.id); err != nil {
				return err
			}
			n++
		}
		return s.log.Append(ctx, tx, audit.Entry{Principal: by, Action: "key_rotate", TargetType: "key",
			Metadata: map[string]any{"key_id": s.kp.KeyID(), "secret_versions": n, "totp": totp}})
	})
	return n, err
}
