package access

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

func person(t *testing.T, p storage.Provider, role string) (Actor, string) {
	id := storagetest.Principal(t, p, "human", role, "active")
	var name string
	if err := p.DB().QueryRow(p.Rebind(`SELECT name FROM principals WHERE id = ?`), id).Scan(&name); err != nil {
		t.Fatal(err)
	}
	return Actor{ID: id}, name
}

func allows(t *testing.T, p storage.Provider, a Actor, perm string, tags ...string) bool {
	perms, err := For(t.Context(), p, p.DB(), a, perm)
	if err != nil {
		t.Fatal(err)
	}
	return perms.Allows(tags)
}

func TestGrantsGroupsAndAdminOnly(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
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
		mid := storagetest.Machine(t, p, user.ID, "ci")
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
		if err := p.DB().QueryRow(p.Rebind(`SELECT COUNT(*) FROM audit_log WHERE principal_id = ? AND result = 'denied'`), user.ID).Scan(&n); err != nil || n != 1 {
			t.Fatalf("grant denial must be audited, got %d (%v)", n, err)
		}
	})
}

// Only an answer about the person is a denial; a database failure must surface as the failure it is.
func TestRequireAdminSeparatesDenialFromDatabaseError(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		ctx := t.Context()
		admin, _ := person(t, p, "admin")
		member, _ := person(t, p, "member")
		if err := requireAdmin(ctx, p, p.DB(), admin.ID); err != nil {
			t.Fatalf("an active admin passes: %v", err)
		}
		for name, id := range map[string]uuid.UUID{"member": member.ID, "unknown": uuid.New()} {
			var de *Error
			if err := requireAdmin(ctx, p, p.DB(), id); !errors.As(err, &de) || de.Code != CodeDenied {
				t.Fatalf("%s: want a denial, got %v", name, err)
			}
		}
		gone, cancel := context.WithCancel(ctx)
		cancel()
		err := requireAdmin(gone, p, p.DB(), admin.ID)
		var de *Error
		if err == nil || errors.As(err, &de) {
			t.Fatalf("a database error must not become a denial: %v", err)
		}
	})
}
