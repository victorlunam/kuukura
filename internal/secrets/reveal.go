package secrets

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/access"
	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/keys"
)

// Value is a decrypted secret. It must never be logged or put in an error.
type Value struct {
	SecretID uuid.UUID
	Name     string
	Kind     string
	Filename string
	Version  int
	Data     []byte
}

// Reveal returns exactly one secret's value. stepUp means the API verified a
// fresh passkey assertion; machines can never reveal.
func (s *Service) Reveal(ctx context.Context, a access.Actor, in Selector, stepUp bool) (Value, error) {
	vals, err := s.fetch(ctx, a, in, "reveal", true, stepUp)
	if err != nil {
		return Value{}, err
	}
	return vals[0], nil
}

// Run returns every readable secret for the selector, failing closed on
// blocked, not permitted or ambiguous names.
func (s *Service) Run(ctx context.Context, a access.Actor, in Selector, stepUp bool) ([]Value, error) {
	return s.fetch(ctx, a, in, "read", false, stepUp)
}

func (s *Service) fetch(ctx context.Context, a access.Actor, in Selector, action string, single, stepUp bool) ([]Value, error) {
	sel, err := in.parse()
	if err != nil {
		return nil, err
	}
	if sel.name == "" && len(sel.tags) == 0 {
		return nil, fail(access.CodeInvalid, "a name or a tag is required")
	}
	var out []Value
	err = s.run(ctx, func(tx *sql.Tx, denied *[]audit.Entry) error {
		all, rows, err := s.readable(ctx, tx, a, sel)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			// A secret the caller may not read looks exactly like one that does not exist: same error, nothing about
			// its tags. (List, update, revoke and archive already work this way.) The admin still sees the attempt,
			// because the denial is audited.
			if sel.name != "" && len(all) > 0 {
				*denied = append(*denied, deniedEntry(a, action, all[0].ID))
			}
			return fail(access.CodeNotFound, "no matching secret")
		}
		if single && len(rows) > 1 {
			return fail(access.CodeAmbiguous, "several secrets match", labels(rows)...)
		}
		// rows come ordered by name, so the first repeated name is the same on every try (a map would pick any)
		seen := map[string][]Info{}
		var order []string
		for _, r := range rows {
			if _, ok := seen[r.Name]; !ok {
				order = append(order, r.Name)
			}
			seen[r.Name] = append(seen[r.Name], r)
		}
		for _, n := range order {
			if g := seen[n]; len(g) > 1 {
				return fail(access.CodeAmbiguous, n+" matches several secrets", labels(g)...)
			}
		}
		var blocked []string
		needStepUp := single
		for _, r := range rows {
			if r.Blocked || r.Version == 0 {
				blocked = append(blocked, r.label())
			}
			needStepUp = needStepUp || r.RequiresAuthorize
		}
		if len(blocked) > 0 {
			return fail(access.CodeBlocked, "blocked until a new value is saved", blocked...)
		}
		if needStepUp {
			if a.Machine {
				*denied = append(*denied, deniedEntry(a, action, rows[0].ID))
				return fail(access.CodeDenied, "not permitted")
			}
			if !stepUp {
				return fail(access.CodeStepUp, "confirmation required")
			}
		}
		// Decrypt everything before the first audit append: that takes the global audit lock, and decrypting can be
		// a network call to KMS, which must not be made while other writers wait on it.
		for _, r := range rows {
			v, err := s.load(ctx, tx, r)
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		for _, r := range rows {
			n := r.Version
			if err := s.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: action, SecretID: &r.ID, Version: &n, IP: a.IP}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func labels(rows []Info) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.label()
	}
	return out
}

func (s *Service) load(ctx context.Context, tx *sql.Tx, r Info) (Value, error) {
	var pl keys.Payload
	var fn sql.NullString
	var fv int
	err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT ciphertext, nonce, wrapped_key, key_id, format_version, filename
		FROM secret_versions WHERE secret_id = ? AND number = ?`), r.ID, r.Version).
		Scan(&pl.Ciphertext, &pl.Nonce, &pl.WrappedKey, &pl.KeyID, &fv, &fn)
	if err != nil {
		return Value{}, err
	}
	pl.FormatVersion = byte(fv)                                    // #nosec G115 -- smallint column
	data, err := keys.Open(ctx, s.kp, r.ID, uint32(r.Version), pl) // #nosec G115 -- version numbers are small
	if err != nil {
		return Value{}, err
	}
	return Value{SecretID: r.ID, Name: r.Name, Kind: r.Kind, Filename: fn.String, Version: r.Version, Data: data}, nil
}
