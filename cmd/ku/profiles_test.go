package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

func testApp(t *testing.T, env map[string]string) (*app, *memStore, *strings.Builder) {
	home := t.TempDir()
	st := &memStore{m: map[string]string{}}
	var out strings.Builder
	a := &app{in: strings.NewReader(""), out: &out, err: &out, getenv: func(k string) string { return env[k] }, store: st, home: home, cwd: filepath.Join(home, "proj", "sub")}
	return a, st, &out
}

func TestProfileResolutionOrder(t *testing.T) {
	env := map[string]string{}
	a, _, _ := testApp(t, env)
	add := func(name, url string) {
		t.Helper()
		if code := a.cmdProfile([]string{"add", name, "--url", url}); code != 0 {
			t.Fatalf("add %s", name)
		}
	}
	add("work", "https://work.example.test")
	add("home", "https://home.example.test")
	add("link", "https://link.example.test")
	add("env", "https://env.example.test")
	if code := a.cmdProfile([]string{"use", "home"}); code != 0 {
		t.Fatal("use")
	}
	url := func(flag string) string {
		t.Helper()
		p, err := a.resolve(flag)
		if err != nil {
			t.Fatal(err)
		}
		return p.url
	}
	// active profile
	if got := url(""); got != "https://home.example.test" {
		t.Fatalf("active: %s", got)
	}
	// folder link profile beats active
	a.cwd = filepath.Join(a.home, "proj")
	if err := a.saveLinks(map[string]link{filepath.Join(a.home, "proj"): {App: "shop", Profile: "link"}}); err != nil {
		t.Fatal(err)
	}
	a.cwd = filepath.Join(a.home, "proj", "sub") // nearest parent link wins
	if got := url(""); got != "https://link.example.test" {
		t.Fatalf("link: %s", got)
	}
	p, _ := a.resolve("")
	if p.app != "shop" {
		t.Fatalf("link app: %q", p.app)
	}
	// KU_PROFILE beats the link
	env["KU_PROFILE"] = "env"
	if got := url(""); got != "https://env.example.test" {
		t.Fatalf("KU_PROFILE: %s", got)
	}
	// KU_URL + KU_TOKEN beats the link too; both KU_URL and KU_PROFILE is an error
	env["KU_PROFILE"] = ""
	env["KU_URL"], env["KU_TOKEN"] = "https://ci.example.test", "ku_x"
	p, err := a.resolve("")
	if err != nil || p.url != "https://ci.example.test" || !p.ephemeral || p.token != "ku_x" {
		t.Fatalf("KU_URL: %+v %v", p, err)
	}
	env["KU_PROFILE"] = "env"
	if _, err := a.resolve(""); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("KU_URL + KU_PROFILE must be an error: %v", err)
	}
	// --profile beats everything
	env["KU_PROFILE"] = ""
	if got := url("work"); got != "https://work.example.test" {
		t.Fatalf("--profile: %s", got)
	}
	if _, err := a.resolve("nope"); err == nil {
		t.Fatal("unknown profile")
	}
	// non-https URLs are refused; a token is never sent over plain http
	if code := a.cmdProfile([]string{"add", "bad", "--url", "http://x.example.test"}); code == 0 {
		t.Fatal("http URL accepted")
	}
}

func TestProfileCommandsAndKeychain(t *testing.T) {
	a, st, out := testApp(t, nil)
	if a.cmdProfile([]string{"add", "work", "--url", "https://work.example.test"}) != 0 || a.cmdProfile([]string{"add", "home", "--url", "https://home.example.test"}) != 0 {
		t.Fatal("add")
	}
	out.Reset()
	a.out = out
	_ = st.Set("work", "ku_tok")
	_ = st.Set("home", "ku_tok2")
	a.cmdProfile([]string{"use", "home"})
	out.Reset()
	a.cmdProfile([]string{"list"})
	if !strings.Contains(out.String(), "* home") || !strings.Contains(out.String(), "  work") {
		t.Fatalf("list marks the active profile:\n%s", out)
	}
	if a.cmdProfile([]string{"remove", "work"}) != 0 {
		t.Fatal("remove")
	}
	if _, err := st.Get("work"); err == nil {
		t.Fatal("removing a profile must delete its Keychain token")
	}
	if _, err := st.Get("home"); err != nil {
		t.Fatal("other tokens stay")
	}
	// tokens never live in the config file
	b, _ := readFile(filepath.Join(a.configDir(), "config.toml"))
	if strings.Contains(b, "ku_tok") {
		t.Fatal("token in config")
	}
}

func TestLoginFlow(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w := newWorld(t, p)
		w.admin() // enrolled admin with a passkey
		// no profile yet: login explains what to do first
		if r := w.ku("", false, nil, "login"); r.code != 1 || !strings.Contains(r.errOut, "ku profile add <name> --url") {
			t.Fatalf("login without a profile: %q", r.errOut)
		}
		if r := w.ku("", false, nil, "login", "--url", w.srv.URL); r.code != 1 {
			t.Fatal("login no longer takes --url")
		}
		mustOK(t, w.ku("", false, nil, "profile", "add", "default", "--url", w.srv.URL))
		r := w.ku("", false, nil, "login")
		if r.code != 0 || !strings.Contains(r.out, "✓ Signed in to default") {
			t.Fatalf("login: %q %q", r.out, r.errOut)
		}
		tok, err := w.store.Get("default")
		if err != nil || !strings.HasPrefix(tok, "ku_") {
			t.Fatal("the token goes to the Keychain")
		}
		cfg, _ := readFile(filepath.Join(w.home, ".config", "kuukura", "config.toml"))
		if strings.Contains(cfg, tok) {
			t.Fatal("never in config files")
		}
		// the session works
		if r := w.ku("", false, nil, "secret", "list"); r.code != 0 {
			t.Fatalf("list after login: %q", r.errOut)
		}
	})
}
