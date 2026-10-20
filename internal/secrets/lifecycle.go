package secrets

import (
	"context"
	"database/sql"

	"github.com/victorlunam/kuukura/internal/access"
	"github.com/victorlunam/kuukura/internal/audit"
)

// Revoke marks the current version compromised; the secret stays blocked until the next Set.
func (s *Service) Revoke(ctx context.Context, a access.Actor, in Selector) ([]string, error) {
	return s.bulk(ctx, a, in, "mark_compromised", func(tx *sql.Tx, r Info) (bool, error) {
		if r.Version == 0 || r.Blocked {
			return false, nil // nothing to do for this one
		}
		_, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE secret_versions SET compromised_at = ?, compromised_by = ? WHERE secret_id = ? AND number = ?`),
			s.p.TimeArg(now()), a.ID, r.ID, r.Version)
		return err == nil, err
	}, true)
}

// Archive soft-deletes; name+tags become reusable.
func (s *Service) Archive(ctx context.Context, a access.Actor, in Selector) ([]string, error) {
	return s.bulk(ctx, a, in, "archive", func(tx *sql.Tx, r Info) (bool, error) {
		_, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE secrets SET archived_at = ?, archived_by = ? WHERE id = ?`), s.p.TimeArg(now()), a.ID, r.ID)
		return err == nil, err
	}, false)
}

// bulk applies fn to every selected, writable secret in one transaction. fn reports whether it changed the
// secret; only those are audited and returned.
func (s *Service) bulk(ctx context.Context, a access.Actor, in Selector, action string, fn func(*sql.Tx, Info) (bool, error), withVersion bool) ([]string, error) {
	sel, err := in.parse()
	if err != nil {
		return nil, err
	}
	if sel.name == "" && len(sel.tags) == 0 {
		return nil, fail(access.CodeInvalid, "a name or a tag is required")
	}
	var names []string
	err = s.run(ctx, func(tx *sql.Tx, denied *[]audit.Entry) error {
		rows, err := s.writable(ctx, tx, a, sel, action, denied)
		if err != nil {
			return err
		}
		for _, r := range rows {
			changed, err := fn(tx, r)
			if err != nil {
				return err
			}
			if !changed {
				continue
			}
			e := audit.Entry{Principal: a.ID, Action: action, SecretID: &r.ID, IP: a.IP}
			if withVersion {
				v := r.Version
				e.Version = &v
			}
			if err := s.log.Append(ctx, tx, e); err != nil {
				return err
			}
			names = append(names, r.label())
		}
		return nil
	})
	return names, err
}
