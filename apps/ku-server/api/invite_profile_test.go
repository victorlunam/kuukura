package api_test

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/auth"
	"github.com/victorlunam/kuukura/internal/auth/authtest"
	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

// The inviter's profile name travels with the invite as the header label only. The "all set" page never picks
// the invitee's profile name: it shows a literal <alias> to replace (pasted unchanged, a shell rejects the `<`).
func TestAllSetPageLeavesTheProfileNameToTheInvitee(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		admin, _ := e.admin()

		r := e.do("POST", "/workspace/invites", admin, map[string]any{"email": "new@example.test", "profile": "some_name"})
		if r.Code != 201 {
			t.Fatalf("invite: %d %s", r.Code, r.Body)
		}
		link, _ := url.Parse(r.json()["link"].(string))
		if link.Query().Get("profile") != "some_name" {
			t.Fatalf("the link carries the profile name: %s", link)
		}
		// an unsafe name is dropped, never put in the link
		bad := e.do("POST", "/workspace/invites", admin, map[string]any{"email": "other@example.test", "profile": "Bad Name<x>"})
		if l, _ := url.Parse(bad.json()["link"].(string)); l.Query().Get("profile") != "" {
			t.Fatalf("unsafe profile name must be dropped: %s", l)
		}

		tok := link.Query().Get("token")
		page := e.do("GET", "/invite?token="+tok+"&profile=some_name", "", nil)
		if !strings.Contains(page.Body.String(), "cli_profile=some_name") {
			t.Fatal("the invite page passes the name on to the sign-in")
		}

		// the whole invitation: Google -> passkey -> "all set" page for that name
		ctx := t.Context()
		u, err := e.auth.StartLogin(tok, auth.CLIParams{Profile: "some_name"})
		if err != nil {
			t.Fatal(err)
		}
		pu, _ := url.Parse(u)
		code := uuid.NewString()
		e.idp.Allow(code, auth.Identity{Subject: "sub-new", Email: "new@example.test", EmailVerified: true})
		pd, err := e.auth.Callback(ctx, pu.Query().Get("state"), code, "203.0.113.9")
		if err != nil || pd.Mode != "enroll" || pd.Profile != "some_name" {
			t.Fatalf("callback: %+v %v", pd, err)
		}
		in, _ := e.tokens.Validate(ctx, pd.Token)
		dev := &authtest.Authenticator{RPID: domain, Origin: "https://" + domain}
		opts, err := e.auth.BeginPasskeyRegistration(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		ob, _ := json.Marshal(opts)
		res, err := e.auth.FinishPasskeyRegistration(ctx, in, dev.Register(t, ob, true), "203.0.113.9")
		if err != nil || res.Redirect != "/auth/done?profile=some_name" {
			t.Fatalf("redirect: %q %v", res.Redirect, err)
		}

		for _, path := range []string{res.Redirect, "/auth/done", "/"} {
			b := e.do("GET", path, "", nil).Body.String()
			if !strings.Contains(b, "ku profile add &lt;alias&gt; --url https://"+domain) || !strings.Contains(b, ">ku login<") ||
				strings.Contains(b, "ku profile add some_name") {
				t.Fatalf("%s: the command must leave the profile name to the person: %s", path, b)
			}
		}
	})
}
