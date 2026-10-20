package access

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var de *Error
	if !errors.As(err, &de) || de.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestCreateApp(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		ctx := t.Context()
		log := audit.New(p)
		ad := NewAdmin(p, log)
		alice, _ := person(t, p, "member")
		bob, bobName := person(t, p, "member")

		if err := ad.CreateApp(ctx, alice, "darwin-cloud"); err != nil {
			t.Fatal(err)
		}
		if !allows(t, p, alice, Write, "app:darwin-cloud") || allows(t, p, bob, Read, "app:darwin-cloud") {
			t.Fatal("the creator gets write, nobody else gets anything")
		}
		var n int
		if err := p.DB().QueryRow(p.Rebind(`SELECT COUNT(*) FROM audit_log WHERE principal_id = ? AND action = 'grant' AND target_type = 'grant' AND result = 'ok'`), alice.ID).Scan(&n); err != nil || n != 1 {
			t.Fatalf("audit rows: %d (%v)", n, err)
		}

		// the app exists now: for another person, and for the creator again
		wantCode(t, ad.CreateApp(ctx, bob, "darwin-cloud"), CodeAppExists)
		wantCode(t, ad.CreateApp(ctx, alice, "darwin-cloud"), CodeAppExists)
		// a grant by an admin also makes an app exist
		admin, _ := person(t, p, "admin")
		if err := ad.Grant(ctx, admin, bobName, Read, []string{"app:shop", "env:dev"}); err != nil {
			t.Fatal(err)
		}
		wantCode(t, ad.CreateApp(ctx, alice, "shop"), CodeAppExists)

		// a live secret makes it exist, even with no grant; an archived one does not
		insert := func(name, tag string, archived bool) {
			var arch any
			if archived {
				arch = p.TimeArg(time.Now())
			}
			if _, err := p.DB().Exec(p.Rebind(`INSERT INTO secrets (id, name, kind, tags, created_by, archived_at) VALUES (?, ?, 'text', ?, ?, ?)`),
				uuid.New(), name, p.TagsArg(storage.Tags{tag}), alice.ID, arch); err != nil {
				t.Fatal(err)
			}
		}
		insert("K", "app:legacy", false)
		insert("K", "app:gone", true)
		wantCode(t, ad.CreateApp(ctx, bob, "legacy"), CodeAppExists)
		if err := ad.CreateApp(ctx, bob, "gone"); err != nil {
			t.Fatalf("an app with only archived secrets is new: %v", err)
		}

		// names follow the tag-value rule
		for _, bad := range []string{"", "Has Space", "UPPER", "a:b", "x/y"} {
			wantCode(t, ad.CreateApp(ctx, bob, bad), CodeInvalid)
		}

		// machines and people who are not active are denied, and the denial is audited
		m := Actor{ID: storagetest.Machine(t, p, alice.ID, "ci"), Machine: true}
		wantCode(t, ad.CreateApp(ctx, m, "ci-app"), CodeDenied)
		off := Actor{ID: storagetest.Principal(t, p, "human", "member", "disabled")}
		wantCode(t, ad.CreateApp(ctx, off, "off-app"), CodeDenied)
		wantCode(t, ad.CreateApp(ctx, Actor{ID: uuid.New()}, "ghost-app"), CodeDenied)
		if err := p.DB().QueryRow(p.Rebind(`SELECT COUNT(*) FROM audit_log WHERE action = 'grant' AND result = 'denied'`)).Scan(&n); err != nil || n < 2 {
			t.Fatalf("denials audited: %d (%v)", n, err)
		}
		if err := log.Verify(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

// Two people creating the same app at once: exactly one wins, the other hears app-exists.
func TestCreateAppConcurrent(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		ctx := t.Context()
		ad := NewAdmin(p, audit.New(p))
		const n = 8
		people := make([]Actor, n)
		for i := range people {
			people[i], _ = person(t, p, "member")
		}
		errs := make([]error, n)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				<-start
				errs[i] = ad.CreateApp(ctx, people[i], "race")
			})
		}
		close(start)
		wg.Wait()
		wins := 0
		for _, err := range errs {
			if err == nil {
				wins++
			} else {
				wantCode(t, err, CodeAppExists)
			}
		}
		var grants int
		if err := p.DB().QueryRow(`SELECT COUNT(*) FROM grants`).Scan(&grants); err != nil || wins != 1 || grants != 1 {
			t.Fatalf("wins %d, grants %d (%v)", wins, grants, err)
		}
	})
}
