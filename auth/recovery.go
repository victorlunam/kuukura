package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/storage"
)

const recoveryCodeCount = 10

func normalizeRecovery(c string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(c))
}

func hashRecovery(c string) []byte {
	h := sha256.Sum256([]byte(normalizeRecovery(c)))
	return h[:]
}

// newRecoveryCodes stores hashes of 10 single-use codes and returns the plain codes once.
func (s *Service) newRecoveryCodes(ctx context.Context, tx *sql.Tx, principal uuid.UUID) ([]string, error) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	codes := make([]string, recoveryCodeCount)
	for i := range codes {
		raw := make([]byte, 10) // 80 bits
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		c := enc.EncodeToString(raw) // 16 chars
		codes[i] = c[:4] + "-" + c[4:8] + "-" + c[8:12] + "-" + c[12:]
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`INSERT INTO recovery_codes (id, principal_id, code_hash) VALUES (?, ?, ?)`), uuid.New(), principal, hashRecovery(codes[i])); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

// VerifyRecovery spends one recovery code and completes the login.
func (s *Service) VerifyRecovery(ctx context.Context, in Info, code, ip string) (string, error) {
	if _, err := s.requireScope(in, ScopeMFA); err != nil {
		return "", err
	}
	var redirect string
	err := storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE recovery_codes SET used_at = ? WHERE principal_id = ? AND code_hash = ? AND used_at IS NULL`),
			s.p.TimeArg(s.now()), in.PrincipalID, hashRecovery(code))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrLogin
		}
		redirect, err = s.finish(ctx, tx, in, ip)
		return err
	})
	if errors.Is(err, ErrLogin) {
		return "", s.failed(ctx, in, ip)
	}
	return redirect, err
}
