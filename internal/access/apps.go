package access

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/storage"
)

// CreateApp gives an active person write access to the app "app:<name>", but only when the app is new: no grant
// mentions the tag and no live secret carries it. An existing app needs an admin's grant. Machines never create apps.
func (ad *Admin) CreateApp(ctx context.Context, a Actor, name string) error {
	if !groupRE.MatchString(name) { // the tag-value rule
		return Fail(CodeInvalid, "app names use a-z, 0-9, dot, dash and underscore (1 to 64 characters)")
	}
	tag := storage.Tags{"app:" + name}
	err := storage.InTx(ctx, ad.p, func(tx *sql.Tx) error {
		// One creator at a time (postgres; sqlite has one connection): the check below then sees the winner's grant.
		if err := ad.p.LockAudit(ctx, tx); err != nil {
			return err
		}
		var kind, status, who string
		err := tx.QueryRowContext(ctx, ad.p.Rebind(`SELECT kind, status, name FROM principals WHERE id = ?`), a.ID).Scan(&kind, &status, &who)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err != nil || a.Machine || kind != "human" || status != "active" {
			return Fail(CodeDenied, "not permitted")
		}
		// The secrets table is read here, not through internal/secrets: access sits below it in the layering.
		gc, ga := ad.p.Contains("tag_selector", tag)
		sc, sa := ad.p.Contains("tags", tag)
		var n int
		if err := tx.QueryRowContext(ctx, ad.p.Rebind(`SELECT (SELECT COUNT(*) FROM grants WHERE `+gc+`) + (SELECT COUNT(*) FROM secrets WHERE archived_at IS NULL AND `+sc+`)`),
			append(ga, sa...)...).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return Fail(CodeAppExists, "app "+name+" already exists")
		}
		id := uuid.New()
		if _, err := tx.ExecContext(ctx, ad.p.Rebind(`INSERT INTO grants (id, subject_type, subject_id, tag_selector, permission) VALUES (?, 'principal', ?, ?, ?)`),
			id, a.ID, ad.p.TagsArg(tag), Write); err != nil {
			return err
		}
		// Recorded as a grant (the audit log has no "app" target); "app" marks it as made by creating the app.
		return ad.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: "grant", IP: a.IP, TargetType: "grant", TargetID: &id,
			Metadata: map[string]any{"subject": who, "permission": Write, "tags": tag, "app": name}})
	})
	var de *Error
	if errors.As(err, &de) && de.Code == CodeDenied {
		_ = ad.log.Record(ctx, audit.Entry{Principal: a.ID, Action: "grant", Result: audit.ResultDenied, IP: a.IP})
	}
	return err
}
