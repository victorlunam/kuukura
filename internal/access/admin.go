package access

import (
	"context"
	"database/sql"
	"errors"
	"regexp"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/storage"
)

// Admin manages groups and grants. Callers must be admins; being admin never grants secret access.
type Admin struct {
	p   storage.Provider
	log *audit.Log
}

func NewAdmin(p storage.Provider, log *audit.Log) *Admin { return &Admin{p, log} }

var groupRE = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)

// requireAdmin fails with a denial unless id is an active human admin. A database error is returned as it is:
// it is not an answer about the person.
func requireAdmin(ctx context.Context, p storage.Provider, q storage.Querier, id uuid.UUID) error {
	var role, status string
	err := q.QueryRowContext(ctx, p.Rebind(`SELECT COALESCE(role, ''), status FROM principals WHERE id = ?`), id).Scan(&role, &status)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err != nil || role != "admin" || status != "active" {
		return Fail(CodeDenied, "not permitted")
	}
	return nil
}

// AdminTx runs fn after an admin check; a failed check is recorded as a denial.
func AdminTx(ctx context.Context, p storage.Provider, log *audit.Log, a Actor, action string, fn func(tx *sql.Tx) error) error {
	err := storage.InTx(ctx, p, func(tx *sql.Tx) error {
		if err := requireAdmin(ctx, p, tx, a.ID); err != nil {
			return err
		}
		return fn(tx)
	})
	var de *Error
	if errors.As(err, &de) && de.Code == CodeDenied {
		_ = log.Record(ctx, audit.Entry{Principal: a.ID, Action: action, Result: audit.ResultDenied, IP: a.IP})
	}
	return err
}

type subject struct {
	typ string
	id  uuid.UUID
}

// resolveSubject finds a principal by name/email, else a group by name.
func resolveSubject(ctx context.Context, p storage.Provider, q storage.Querier, name string) (subject, error) {
	var id uuid.UUID
	err := q.QueryRowContext(ctx, p.Rebind(`SELECT id FROM principals WHERE name = ?`), name).Scan(&id)
	if err == nil {
		return subject{"principal", id}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return subject{}, err
	}
	err = q.QueryRowContext(ctx, p.Rebind(`SELECT id FROM groups WHERE name = ?`), name).Scan(&id)
	if err == nil {
		return subject{"group", id}, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return subject{}, Fail(CodeNotFound, "unknown identity or group: "+name)
	}
	return subject{}, err
}

// Grant gives an identity or group read|write on secrets containing all the tags.
func (ad *Admin) Grant(ctx context.Context, a Actor, who, perm string, tags []string) error {
	sel, err := normalizeSelector(perm, tags)
	if err != nil {
		return err
	}
	return AdminTx(ctx, ad.p, ad.log, a, "grant", func(tx *sql.Tx) error {
		sub, err := resolveSubject(ctx, ad.p, tx, who)
		if err != nil {
			return err
		}
		id := uuid.New()
		if _, err := tx.ExecContext(ctx, ad.p.Rebind(`INSERT INTO grants (id, subject_type, subject_id, tag_selector, permission) VALUES (?, ?, ?, ?, ?)`),
			id, sub.typ, sub.id, ad.p.TagsArg(sel), perm); err != nil {
			return err
		}
		return ad.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: "grant", IP: a.IP, TargetType: "grant", TargetID: &id,
			Metadata: map[string]any{"subject": who, "permission": perm, "tags": sel}})
	})
}

// Ungrant removes the grants of an identity or group for exactly these tags.
func (ad *Admin) Ungrant(ctx context.Context, a Actor, who string, tags []string) error {
	sel, err := normalizeSelector(Read, tags)
	if err != nil {
		return err
	}
	return AdminTx(ctx, ad.p, ad.log, a, "revoke_grant", func(tx *sql.Tx) error {
		sub, err := resolveSubject(ctx, ad.p, tx, who)
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, ad.p.Rebind(`SELECT id FROM grants WHERE subject_type = ? AND subject_id = ? AND tag_selector = ?`), sub.typ, sub.id, ad.p.TagsArg(sel))
		if err != nil {
			return err
		}
		var ids []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		_ = rows.Close()
		if len(ids) == 0 {
			return Fail(CodeNotFound, "no such grant")
		}
		for _, id := range ids {
			if _, err := tx.ExecContext(ctx, ad.p.Rebind(`DELETE FROM grants WHERE id = ?`), id); err != nil {
				return err
			}
			if err := ad.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: "revoke_grant", IP: a.IP, TargetType: "grant", TargetID: &id,
				Metadata: map[string]any{"subject": who, "tags": sel}}); err != nil {
				return err
			}
		}
		return nil
	})
}

// SetMembers adds and removes group members (by identity name); the group is created on first use.
func (ad *Admin) SetMembers(ctx context.Context, a Actor, group string, add, remove []string) error {
	if !groupRE.MatchString(group) {
		return Fail(CodeInvalid, "invalid group name")
	}
	return AdminTx(ctx, ad.p, ad.log, a, "group_add", func(tx *sql.Tx) error {
		var gid uuid.UUID
		err := tx.QueryRowContext(ctx, ad.p.Rebind(`SELECT id FROM groups WHERE name = ?`), group).Scan(&gid)
		if errors.Is(err, sql.ErrNoRows) {
			var taken int
			if err := tx.QueryRowContext(ctx, ad.p.Rebind(`SELECT COUNT(*) FROM principals WHERE name = ?`), group).Scan(&taken); err != nil {
				return err
			}
			if taken > 0 {
				return Fail(CodeConflict, "that name belongs to an identity")
			}
			gid = uuid.New()
			_, err = tx.ExecContext(ctx, ad.p.Rebind(`INSERT INTO groups (id, name) VALUES (?, ?)`), gid, group)
		}
		if err != nil {
			return err
		}
		change := func(names []string, action string, qs ...string) error {
			for _, n := range names {
				var pid uuid.UUID
				if err := tx.QueryRowContext(ctx, ad.p.Rebind(`SELECT id FROM principals WHERE name = ?`), n).Scan(&pid); err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return Fail(CodeNotFound, "unknown identity: "+n)
					}
					return err
				}
				for _, q := range qs {
					if _, err := tx.ExecContext(ctx, ad.p.Rebind(q), gid, pid); err != nil {
						return err
					}
				}
				if err := ad.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: action, IP: a.IP, TargetType: "group", TargetID: &gid,
					Metadata: map[string]any{"group": group, "member": n}}); err != nil {
					return err
				}
			}
			return nil
		}
		if err := change(add, "group_add", `DELETE FROM group_members WHERE group_id = ? AND principal_id = ?`, // idempotent add
			`INSERT INTO group_members (group_id, principal_id) VALUES (?, ?)`); err != nil {
			return err
		}
		return change(remove, "group_remove", `DELETE FROM group_members WHERE group_id = ? AND principal_id = ?`)
	})
}

func normalizeSelector(perm string, tags []string) (storage.Tags, error) {
	if perm != Read && perm != Write {
		return nil, Fail(CodeInvalid, "permission must be read or write")
	}
	sel, err := storage.NormalizeTags(tags)
	if err != nil {
		return nil, Fail(CodeInvalid, err.Error())
	}
	if len(sel) == 0 {
		return nil, Fail(CodeInvalid, "at least one tag is required")
	}
	return sel, nil
}
