// Package secrets is the secrets domain: versions, revoke, archive, uniqueness, bulk changes.
package secrets

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/access"
	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/keys"
	"github.com/victorlunam/kuukura/storage"
)

const (
	MaxText = 64 << 10
	MaxFile = 1 << 20
)

const (
	CodeNotFound     = access.CodeNotFound
	CodeDenied       = access.CodeDenied
	CodeAmbiguous    = access.CodeAmbiguous
	CodeBlocked      = access.CodeBlocked
	CodeClash        = access.CodeClash
	CodeStepUp       = access.CodeStepUp
	CodeWouldCreate  = access.CodeWouldCreate
	CodeInvalid      = access.CodeInvalid
	CodeNeedsOne     = access.CodeNeedsOne
	CodeKindMismatch = access.CodeKindMismatch
)

// Error is the shared domain error (see access.Error).
type Error = access.Error

func fail(code, msg string, items ...string) *Error { return access.Fail(code, msg, items...) }

var nameRE = regexp.MustCompile(`^[A-Z0-9_]{1,128}$`)

// Selector is an optional name plus tags, ANDed.
type Selector struct {
	Name string
	Tags []string
}

type selector struct {
	name string
	tags storage.Tags
}

func (s Selector) parse() (selector, error) {
	var out selector
	if s.Name != "" {
		out.name = strings.ToUpper(s.Name)
		if !nameRE.MatchString(out.name) {
			return out, fail(CodeInvalid, "invalid name")
		}
	}
	t, err := storage.NormalizeTags(s.Tags)
	if err != nil {
		return out, fail(CodeInvalid, err.Error())
	}
	out.tags = t
	return out, nil
}

// uniqueKeys rejects a secret with two values for one tag key (env:dev env:prod).
func uniqueKeys(t storage.Tags) error {
	seen := map[string]bool{}
	for _, x := range t {
		if k := tagKey(x); seen[k] {
			return fail(CodeInvalid, "a tag key can only be used once: "+k)
		} else {
			seen[k] = true
		}
	}
	return nil
}

// Info is the listable view of a secret: never a value.
type Info struct {
	ID                uuid.UUID
	Name, Kind        string
	Version           int
	Tags              storage.Tags
	RequiresAuthorize bool
	Blocked           bool
}

func (i Info) label() string { return strings.TrimSpace(i.Name + " " + strings.Join(i.Tags, " ")) }

type Service struct {
	p   storage.Provider
	kp  keys.KeyProvider
	log *audit.Log
}

func New(p storage.Provider, kp keys.KeyProvider, log *audit.Log) *Service {
	return &Service{p, kp, log}
}

func (s *Service) resolve(ctx context.Context, q storage.Querier, sel selector) ([]Info, error) {
	query := `SELECT s.id, s.name, s.kind, s.tags, s.requires_authorize, COALESCE(v.number, 0), COALESCE(v.compromised_at IS NOT NULL, false)
		FROM secrets s LEFT JOIN secret_versions v ON v.id = s.current_version_id
		WHERE s.archived_at IS NULL`
	var args []any
	if sel.name != "" {
		query += ` AND s.name = ?`
		args = append(args, sel.name)
	}
	cond, a := s.p.Contains("s.tags", sel.tags)
	query += ` AND ` + cond + ` ORDER BY s.name, s.id`
	args = append(args, a...)
	rows, err := q.QueryContext(ctx, s.p.Rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Info
	for rows.Next() {
		var i Info
		if err := rows.Scan(&i.ID, &i.Name, &i.Kind, &i.Tags, &i.RequiresAuthorize, &i.Version, &i.Blocked); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// run executes fn in a transaction and records any denials after rollback.
func (s *Service) run(ctx context.Context, fn func(tx *sql.Tx, denied *[]audit.Entry) error) error {
	var denied []audit.Entry
	err := storage.InTx(ctx, s.p, func(tx *sql.Tx) error { return fn(tx, &denied) })
	for _, d := range denied {
		if rerr := s.log.Record(ctx, d); rerr != nil {
			return rerr
		}
	}
	return err
}

func deniedEntry(a access.Actor, action string, id uuid.UUID) audit.Entry {
	return audit.Entry{Principal: a.ID, Action: action, SecretID: &id, Result: audit.ResultDenied, IP: a.IP}
}

// visible keeps only the secrets the actor may read; unreadable ones are treated as absent.
func (s *Service) visible(ctx context.Context, tx storage.Querier, a access.Actor, sel selector) ([]Info, error) {
	rows, err := s.resolve(ctx, tx, sel)
	if err != nil {
		return nil, err
	}
	perm, err := access.For(ctx, s.p, tx, a, access.Read)
	if err != nil {
		return nil, err
	}
	var out []Info
	for _, r := range rows {
		if perm.Allows(r.Tags) {
			out = append(out, r)
		}
	}
	return out, nil
}

// List returns the secrets the actor can read (name, version, tags).
func (s *Service) List(ctx context.Context, a access.Actor, in Selector) ([]Info, error) {
	sel, err := in.parse()
	if err != nil {
		return nil, err
	}
	var out []Info
	err = s.run(ctx, func(tx *sql.Tx, _ *[]audit.Entry) error {
		var err error
		if out, err = s.visible(ctx, tx, a, sel); err != nil {
			return err
		}
		return s.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: "list", IP: a.IP, Metadata: map[string]any{"count": len(out)}})
	})
	return out, err
}

// writable is visible() plus a write check; readable-but-not-writable secrets deny.
func (s *Service) writable(ctx context.Context, tx *sql.Tx, a access.Actor, sel selector, action string, denied *[]audit.Entry) ([]Info, error) {
	rows, err := s.visible(ctx, tx, a, sel)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fail(CodeNotFound, "no matching secret")
	}
	perm, err := access.For(ctx, s.p, tx, a, access.Write)
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, r := range rows {
		if !perm.Allows(r.Tags) {
			bad = append(bad, r.label())
			*denied = append(*denied, deniedEntry(a, action, r.ID))
		}
	}
	if len(bad) > 0 {
		return nil, fail(CodeDenied, "not permitted", bad...)
	}
	return rows, nil
}

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
		return SetResult{}, fail(CodeInvalid, "name is required")
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
		return SetResult{}, fail(CodeInvalid, "invalid kind")
	case in.Generate && kind == "text":
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return SetResult{}, err
		}
		value = []byte(base64.RawURLEncoding.EncodeToString(raw))
	case in.Generate:
		return SetResult{}, fail(CodeInvalid, "cannot generate a file")
	}
	if len(value) == 0 {
		return SetResult{}, fail(CodeInvalid, "empty value")
	}
	limit := MaxText
	filename := ""
	if kind == "file" {
		limit = MaxFile
		if filename = filepath.Base(in.Filename); in.Filename == "" || filename == "." || filename == "/" {
			return SetResult{}, fail(CodeInvalid, "file name is required")
		}
	}
	if len(value) > limit {
		return SetResult{}, fail(CodeInvalid, fmt.Sprintf("value too large (max %d bytes)", limit))
	}

	var res SetResult
	err = s.run(ctx, func(tx *sql.Tx, denied *[]audit.Entry) error {
		perm, err := access.For(ctx, s.p, tx, a, access.Write)
		if err != nil {
			return err
		}
		var id uuid.UUID
		var existingKind string
		err = tx.QueryRowContext(ctx, s.p.Rebind(`SELECT id, kind FROM secrets WHERE name = ? AND tags = ? AND archived_at IS NULL`),
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
			return fail(CodeDenied, "not permitted")
		}
		number := 1
		if exists {
			if existingKind != kind {
				return fail(CodeKindMismatch, "this secret is a different kind")
			}
			if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT COALESCE(MAX(number), 0) + 1 FROM secret_versions WHERE secret_id = ?`), id).Scan(&number); err != nil {
				return err
			}
		} else {
			if !in.Create {
				return fail(CodeWouldCreate, "secret does not exist yet")
			}
			id = uuid.New()
			if _, err := tx.ExecContext(ctx, s.p.Rebind(`INSERT INTO secrets (id, name, kind, description, tags, created_by) VALUES (?, ?, ?, ?, ?, ?)`),
				id, sel.name, kind, in.Description, s.p.TagsArg(sel.tags), a.ID); err != nil {
				return err
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
			return err
		}
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE secrets SET current_version_id = ? WHERE id = ?`), vid, id); err != nil {
			return err
		}
		res = SetResult{Name: sel.name, Version: number, Created: number == 1}
		return s.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: "create", SecretID: &id, Version: &number, IP: a.IP})
	})
	return res, err
}

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
		return nil, fail(CodeInvalid, "a name or a tag is required")
	}
	var out []Value
	err = s.run(ctx, func(tx *sql.Tx, denied *[]audit.Entry) error {
		all, err := s.resolve(ctx, tx, sel)
		if err != nil {
			return err
		}
		perm, err := access.For(ctx, s.p, tx, a, access.Read)
		if err != nil {
			return err
		}
		var rows []Info
		for _, r := range all {
			if perm.Allows(r.Tags) {
				rows = append(rows, r)
			}
		}
		if len(rows) == 0 {
			if sel.name != "" && len(all) > 0 {
				*denied = append(*denied, deniedEntry(a, action, all[0].ID))
				return fail(CodeDenied, "not permitted", all[0].label())
			}
			return fail(CodeNotFound, "no matching secret")
		}
		if single && len(rows) > 1 {
			return fail(CodeAmbiguous, "several secrets match", labels(rows)...)
		}
		seen := map[string][]Info{}
		for _, r := range rows {
			seen[r.Name] = append(seen[r.Name], r)
		}
		for _, g := range seen {
			if len(g) > 1 {
				return fail(CodeAmbiguous, g[0].Name+" matches several secrets", labels(g)...)
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
			return fail(CodeBlocked, "blocked until a new value is saved", blocked...)
		}
		if needStepUp {
			if a.Machine {
				*denied = append(*denied, deniedEntry(a, action, rows[0].ID))
				return fail(CodeDenied, "not permitted")
			}
			if !stepUp {
				return fail(CodeStepUp, "confirmation required")
			}
		}
		for _, r := range rows {
			v, err := s.load(ctx, tx, r)
			if err != nil {
				return err
			}
			n := r.Version
			if err := s.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: action, SecretID: &r.ID, Version: &n, IP: a.IP}); err != nil {
				return err
			}
			out = append(out, v)
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

// Revoke marks the current version compromised; the secret stays blocked until the next Set.
func (s *Service) Revoke(ctx context.Context, a access.Actor, in Selector) ([]string, error) {
	return s.bulk(ctx, a, in, "mark_compromised", func(tx *sql.Tx, r Info) (map[string]any, error) {
		if r.Version == 0 || r.Blocked {
			return nil, nil
		}
		_, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE secret_versions SET compromised_at = ?, compromised_by = ? WHERE secret_id = ? AND number = ?`),
			s.p.TimeArg(now()), a.ID, r.ID, r.Version)
		return map[string]any{}, err
	}, true)
}

// Archive soft-deletes; name+tags become reusable.
func (s *Service) Archive(ctx context.Context, a access.Actor, in Selector) ([]string, error) {
	return s.bulk(ctx, a, in, "archive", func(tx *sql.Tx, r Info) (map[string]any, error) {
		_, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE secrets SET archived_at = ?, archived_by = ? WHERE id = ?`), s.p.TimeArg(now()), a.ID, r.ID)
		return map[string]any{}, err
	}, false)
}

// bulk applies fn to every selected, writable secret in one transaction.
func (s *Service) bulk(ctx context.Context, a access.Actor, in Selector, action string, fn func(*sql.Tx, Info) (map[string]any, error), withVersion bool) ([]string, error) {
	sel, err := in.parse()
	if err != nil {
		return nil, err
	}
	if sel.name == "" && len(sel.tags) == 0 {
		return nil, fail(CodeInvalid, "a name or a tag is required")
	}
	var names []string
	err = s.run(ctx, func(tx *sql.Tx, denied *[]audit.Entry) error {
		rows, err := s.writable(ctx, tx, a, sel, action, denied)
		if err != nil {
			return err
		}
		for _, r := range rows {
			meta, err := fn(tx, r)
			if err != nil {
				return err
			}
			if meta == nil {
				continue // nothing to do for this one
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
