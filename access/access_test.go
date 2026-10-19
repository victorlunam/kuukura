package access

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

var ctx = context.Background()

func person(t *testing.T, p storage.Provider, role string) (Actor, string) {
	id := uuid.New()
	name := id.String()[:8] + "@example.test"
	if _, err := p.DB().Exec(p.Rebind(`INSERT INTO principals (id, kind, name, email, role, status) VALUES (?, 'human', ?, ?, ?, 'active')`), id, name, name, role); err != nil {
		t.Fatal(err)
	}
	return Actor{ID: id}, name
}

func allows(t *testing.T, p storage.Provider, a Actor, perm string, tags ...string) bool {
	perms, err := For(ctx, p, p.DB(), a, perm)
	if err != nil {
		t.Fatal(err)
	}
	return perms.Allows(tags)
}

func TestGrantsGroupsAndAdminOnly(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		log := audit.New(p)
		ad := NewAdmin(p, log)
		admin, _ := person(t, p, "admin")
		user, userName := person(t, p, "member")

		if allows(t, p, admin, Read, "app:shop") {
			t.Fatal("admin role must not grant secret access")
		}
		var de *Error
		if err := ad.Grant(ctx, user, userName, Read, []string{"app:shop"}); !errors.As(err, &de) || de.Code != CodeDenied {
			t.Fatalf("non-admin grant: %v", err)
		}
		if err := ad.Grant(ctx, admin, userName, "admin", []string{"app:shop"}); err == nil {
			t.Fatal("there is no admin permission level")
		}
		if err := ad.Grant(ctx, admin, userName, Read, nil); err == nil {
			t.Fatal("tags are required")
		}

		// direct grant, containment semantics
		if err := ad.Grant(ctx, admin, userName, Read, []string{"app:shop", "env:dev"}); err != nil {
			t.Fatal(err)
		}
		if !allows(t, p, user, Read, "app:shop", "env:dev", "team:pay") || allows(t, p, user, Read, "app:shop") || allows(t, p, user, Write, "app:shop", "env:dev") {
			t.Fatal("grant containment / permission level")
		}

		// group grant
		if err := ad.SetMembers(ctx, admin, "payments", []string{userName}, nil); err != nil {
			t.Fatal(err)
		}
		if err := ad.SetMembers(ctx, admin, "payments", []string{userName}, nil); err != nil {
			t.Fatalf("adding twice is fine: %v", err)
		}
		if err := ad.Grant(ctx, admin, "payments", Write, []string{"team:pay"}); err != nil {
			t.Fatal(err)
		}
		if !allows(t, p, user, Write, "team:pay") || !allows(t, p, user, Read, "team:pay", "env:prod") {
			t.Fatal("group grant (write implies read)")
		}
		if err := ad.SetMembers(ctx, admin, "payments", nil, []string{userName}); err != nil {
			t.Fatal(err)
		}
		if allows(t, p, user, Write, "team:pay") {
			t.Fatal("removed member keeps access")
		}

		// machine: own grants AND owner's
		mid := uuid.New()
		if _, err := p.DB().Exec(p.Rebind(`INSERT INTO principals (id, kind, name, owner_id, status) VALUES (?, 'machine', 'ci', ?, 'active')`), mid, user.ID); err != nil {
			t.Fatal(err)
		}
		m := Actor{ID: mid, Machine: true}
		if err := ad.Grant(ctx, admin, "ci", Read, []string{"team:pay"}); err != nil {
			t.Fatal(err)
		}
		if allows(t, p, m, Read, "team:pay") {
			t.Fatal("machine must not exceed its owner (owner lost team:pay)")
		}
		if err := ad.Grant(ctx, admin, "ci", Read, []string{"app:shop", "env:dev"}); err != nil {
			t.Fatal(err)
		}
		if !allows(t, p, m, Read, "app:shop", "env:dev") {
			t.Fatal("machine within its owner's grants")
		}

		if err := ad.Ungrant(ctx, admin, userName, []string{"env:dev", "app:shop"}); err != nil {
			t.Fatal(err)
		}
		if allows(t, p, user, Read, "app:shop", "env:dev") {
			t.Fatal("ungrant")
		}
		if err := ad.Ungrant(ctx, admin, userName, []string{"env:dev", "app:shop"}); err == nil {
			t.Fatal("ungrant of a missing grant must say so")
		}
		if err := log.Verify(ctx); err != nil {
			t.Fatal(err)
		}
		var n int
		_ = p.DB().QueryRow(p.Rebind(`SELECT COUNT(*) FROM audit_log WHERE principal_id = ? AND result = 'denied'`), user.ID).Scan(&n)
		if n != 1 {
			t.Fatalf("grant denial must be audited, got %d", n)
		}
	})
}
