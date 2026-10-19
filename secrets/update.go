package secrets

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"time"

	"github.com/victorlunam/kuukura/access"
	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/storage"
)

func now() time.Time { return time.Now().UTC() }

// Change is a metadata-only edit; it never creates a version.
type Change struct {
	Rename     string
	AddTags    []string
	RemoveTags []string
	Authorize  *bool
}

// Update edits metadata of every selected secret, all or nothing. stepUp is
// required to turn requires_authorize off.
func (s *Service) Update(ctx context.Context, a access.Actor, in Selector, ch Change, stepUp bool) ([]string, error) {
	sel, err := in.parse()
	if err != nil {
		return nil, err
	}
	if sel.name == "" && len(sel.tags) == 0 {
		return nil, fail(CodeInvalid, "a name or a tag is required")
	}
	add, err := storage.NormalizeTags(ch.AddTags)
	if err != nil {
		return nil, fail(CodeInvalid, err.Error())
	}
	rem, err := storage.NormalizeTags(ch.RemoveTags)
	if err != nil {
		return nil, fail(CodeInvalid, err.Error())
	}
	rename := strings.ToUpper(ch.Rename)
	if rename != "" && !nameRE.MatchString(rename) {
		return nil, fail(CodeInvalid, "invalid name")
	}
	if rename == "" && len(add) == 0 && len(rem) == 0 && ch.Authorize == nil {
		return nil, fail(CodeInvalid, "nothing to change")
	}
	var names []string
	err = s.run(ctx, func(tx *sql.Tx, denied *[]audit.Entry) error {
		rows, err := s.writable(ctx, tx, a, sel, "update", denied)
		if err != nil {
			return err
		}
		// Turning the confirmation off needs a confirmation of its own. It is asked only after the permission
		// check: someone who may not change the secret is refused outright and never sent through a confirmation.
		if ch.Authorize != nil && !*ch.Authorize {
			if a.Machine {
				*denied = append(*denied, deniedEntry(a, "update", rows[0].ID))
				return fail(CodeDenied, "not permitted")
			}
			if !stepUp {
				return fail(CodeStepUp, "confirmation required")
			}
		}
		if rename != "" && len(rows) != 1 {
			return fail(CodeNeedsOne, "--name works on exactly one secret")
		}
		perm, err := access.For(ctx, s.p, tx, a, access.Write)
		if err != nil {
			return err
		}
		type plan struct {
			Info
			name string
			tags storage.Tags
		}
		plans := make([]plan, len(rows))
		selected := map[string]bool{}
		for i, r := range rows {
			selected[r.ID.String()] = true
			// adding key:value replaces any existing value for that key
			t := slices.DeleteFunc(slices.Clone(r.Tags), func(x string) bool {
				return slices.Contains(rem, x) || slices.ContainsFunc(add, func(n string) bool { return tagKey(n) == tagKey(x) })
			})
			nt, err := storage.NormalizeTags(append(t, add...))
			if err == nil {
				err = uniqueKeys(nt)
			}
			if err != nil {
				return fail(CodeInvalid, err.Error(), r.label())
			}
			n := r.Name
			if rename != "" {
				n = rename
			}
			if !perm.Allows(nt) {
				*denied = append(*denied, deniedEntry(a, "update", r.ID))
				return fail(CodeDenied, "not permitted", r.label())
			}
			plans[i] = plan{r, n, nt}
		}
		// Uniqueness: against every other active secret and among the new identities.
		others, err := s.resolve(ctx, tx, selector{})
		if err != nil {
			return err
		}
		taken := map[string]bool{}
		for _, o := range others {
			if !selected[o.ID.String()] {
				taken[o.Name+"|"+strings.Join(o.Tags, ",")] = true
			}
		}
		var clashes []string
		for _, p := range plans {
			k := p.name + "|" + strings.Join(p.tags, ",")
			if taken[k] {
				clashes = append(clashes, strings.TrimSpace(p.name+" "+strings.Join(p.tags, " ")))
			}
			taken[k] = true
		}
		if len(clashes) > 0 {
			return fail(CodeClash, "would clash with existing secrets", clashes...)
		}
		for _, p := range plans {
			authorize := p.RequiresAuthorize
			if ch.Authorize != nil {
				authorize = *ch.Authorize
			}
			if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE secrets SET name = ?, tags = ?, requires_authorize = ? WHERE id = ?`),
				p.name, s.p.TagsArg(p.tags), authorize, p.ID); err != nil {
				return err
			}
			meta := map[string]any{}
			if p.name != p.Name {
				meta["renamed_from"] = p.Name
				meta["renamed_to"] = p.name
			}
			if len(add) > 0 {
				meta["tags_added"] = toAny(add)
			}
			if len(rem) > 0 {
				meta["tags_removed"] = toAny(rem)
			}
			if authorize != p.RequiresAuthorize {
				meta["requires_authorize"] = authorize
			}
			id := p.ID
			if err := s.log.Append(ctx, tx, audit.Entry{Principal: a.ID, Action: "update", SecretID: &id, IP: a.IP, Metadata: meta}); err != nil {
				return err
			}
			names = append(names, strings.TrimSpace(p.name+" "+strings.Join(p.tags, " ")))
		}
		return nil
	})
	return names, err
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func tagKey(t string) string { k, _, _ := strings.Cut(t, ":"); return k }
