package secrets

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/access"
	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/keys"
)

const (
	MaxText = 64 << 10
	MaxFile = 1 << 20
)

// SetInput creates a secret or adds a version when name+tags match exactly.
type SetInput struct {
	Name        string
	Tags        []string
	Kind        string // "text" (default) or "file"
	Value       []byte
	Filename    string
	Description string
	Generate    bool // server-generated value, never returned
	Create      bool // confirm creation when no exact match exists
}

type SetResult struct {
	Name    string
	Version int
	Created bool
}

func (s *Service) Set(ctx context.Context, a access.Actor, in SetInput) (SetResult, error) {
	sel, err := Selector{Name: in.Name, Tags: in.Tags}.parse()
	if err != nil {
		return SetResult{}, err
	}
	if sel.name == "" {
		return SetResult{}, fail(access.CodeInvalid, "name is required")
	}
	if err := uniqueKeys(sel.tags); err != nil {
		return SetResult{}, err
	}
	kind := in.Kind
	if kind == "" {
		kind = "text"
	}
	value := in.Value
	switch {
	case kind != "text" && kind != "file":
		return SetResult{}, fail(access.CodeInvalid, "invalid kind")
	case in.Generate && kind == "text":
		raw := make([]byte, 32)
		rand.Read(raw)
		value = []byte(base64.RawURLEncoding.EncodeToString(raw))
	case in.Generate:
		return SetResult{}, fail(access.CodeInvalid, "cannot generate a file")
	}
	if len(value) == 0 {
		return SetResult{}, fail(access.CodeInvalid, "empty value")
	}
	limit := MaxText
	filename := ""
	if kind == "file" {
		limit = MaxFile
		if filename = filepath.Base(in.Filename); in.Filename == "" || filename == "." || filename == "/" {
			return SetResult{}, fail(access.CodeInvalid, "file name is required")
		}
	}
	if len(value) > limit {
		return SetResult{}, fail(access.CodeInvalid, fmt.Sprintf("value too large (max %d bytes)", limit))
	}

	var res SetResult
	err = s.run(ctx, func(tx *sql.Tx, denied *[]audit.Entry) error {
		perm, err := access.For(ctx, s.p, tx, a, access.Write)
		if err != nil {
			return err
		}
		var id uuid.UUID
		var existingKind string
		// The row lock makes writers of one secret take turns, so each reads the version number the one before left.
		err = tx.QueryRowContext(ctx, s.p.Rebind(`SELECT id, kind FROM secrets WHERE name = ? AND tags = ? AND archived_at IS NULL`+s.p.ForUpdate()),
			sel.name, s.p.TagsArg(sel.tags)).Scan(&id, &existingKind)
		exists := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if !perm.Allows(sel.tags) {
			// A secret we cannot write may exist; the answer is the same either way.
			e := audit.Entry{Principal: a.ID, Action: "create", Result: audit.ResultDenied, IP: a.IP, Metadata: map[string]any{"name": sel.name}}
			if exists {
				e.SecretID = &id
			}
			*denied = append(*denied, e)
			return fail(access.CodeDenied, "not permitted")
		}
		number := 1
		if exists {
			if existingKind != kind {
				return fail(access.CodeKindMismatch, "this secret is a different kind")
			}
			if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT COALESCE(MAX(number), 0) + 1 FROM secret_versions WHERE secret_id = ?`), id).Scan(&number); err != nil {
				return err
			}
		} else {
			if !in.Create {
				return fail(access.CodeWouldCreate, "secret does not exist yet")
			}
			id = uuid.New()
			// Nothing to lock yet: of two creators of one identity the second loses on the unique index.
			if _, err := tx.ExecContext(ctx, s.p.Rebind(`INSERT INTO secrets (id, name, kind, description, tags, created_by) VALUES (?, ?, ?, ?, ?, ?)`),
				id, sel.name, kind, in.Description, s.p.TagsArg(sel.tags), a.ID); err != nil {
				return conflict(err)
			}
		}
		pl, err := keys.Seal(ctx, s.kp, id, uint32(number), value) // #nosec G115 -- version numbers are small
		if err != nil {
			return err
		}
		vid := uuid.New()
		var fn any
		if filename != "" {
			fn = filename
		}
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`INSERT INTO secret_versions
			(id, secret_id, number, ciphertext, nonce, wrapped_key, key_id, format_version, filename, created_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			vid, id, number, pl.Ciphertext, pl.Nonce, pl.WrappedKey, pl.KeyID, int(pl.FormatVersion), fn, a.ID); err != nil {
			return conflict(err)
		}
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE secrets SET current_version_id = ? WHERE id = ?`), vid, id); err != nil {
			return err
		}
		res = SetResult{Name: sel.name, Version: number, Created: number == 1}
		return s.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: "create", SecretID: &id, Version: &number, IP: a.IP})
	})
	return res, err
}
