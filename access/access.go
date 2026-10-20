// Package access decides who may touch which secrets: grants, groups, checks.
package access

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/storage"
)

const (
	Read  = "read"
	Write = "write"
)

// Actor is the authenticated caller of a domain operation.
type Actor struct {
	ID      uuid.UUID
	Machine bool
	IP      string
}

// Perm is what an actor may do: every layer must allow a secret. A human has
// one layer (their grants); a machine has two (its own grants and its owner's),
// so a machine never exceeds its creator.
type Perm struct{ layers [][]storage.Tags }

// Allows reports whether a secret with these tags is permitted.
func (p Perm) Allows(tags storage.Tags) bool {
	for _, layer := range p.layers {
		ok := false
		for _, sel := range layer {
			if storage.Subset(sel, tags) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// For loads the actor's permission for "read" or "write". Write implies read.
func For(ctx context.Context, sp storage.Provider, q storage.Querier, a Actor, perm string) (Perm, error) {
	var p Perm
	l, err := selectors(ctx, sp, q, a.ID, perm)
	if err != nil {
		return p, err
	}
	p.layers = append(p.layers, l)
	if a.Machine {
		var owner uuid.NullUUID
		if err := q.QueryRowContext(ctx, sp.Rebind(`SELECT owner_id FROM principals WHERE id = ?`), a.ID).Scan(&owner); err != nil {
			return p, err
		}
		var ol []storage.Tags
		if owner.Valid {
			if ol, err = selectors(ctx, sp, q, owner.UUID, perm); err != nil {
				return p, err
			}
		}
		p.layers = append(p.layers, ol)
	}
	return p, nil
}

func selectors(ctx context.Context, sp storage.Provider, q storage.Querier, id uuid.UUID, perm string) ([]storage.Tags, error) {
	perms := []any{Write}
	if perm == Read {
		perms = []any{Read, Write}
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(perms)), ",")
	rows, err := q.QueryContext(ctx, sp.Rebind(`SELECT tag_selector FROM grants g WHERE g.permission IN (`+ph+`) AND (
		(g.subject_type = 'principal' AND g.subject_id = ?) OR
		(g.subject_type = 'group' AND g.subject_id IN (SELECT group_id FROM group_members WHERE principal_id = ?)))`),
		append(perms, id, id)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.Tags
	for rows.Next() {
		var t storage.Tags
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
