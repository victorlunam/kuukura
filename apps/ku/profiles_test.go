package main

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

func testApp(t *testing.T, env map[string]string) (*app, *memStore, *strings.Builder) {
	home := t.TempDir()
	st := &memStore{m: map[string]string{}}
	var out strings.Builder
	a := &app{in: strings.NewReader(""), out: &out, err: &out, getenv: func(k string) string { return env[k] }, store: st, home: home, cwd: filepath.Join(home, "proj", "sub")}
	return a, st, &out
}

// A profile name is also a file name, so these must never be accepted.
func TestProfileNamesCannotBeAPath(t *testing.T) {
	a, _, _ := testApp(t, nil)
	for _, bad := range []string{".", "..", ".hidden", "-x", "a/b", `a\b`, "A", "a b", ""} {
		if a.cmdProfile([]string{"add", bad, "--url", "https://x.example.test"}) == 0 {
			t.Fatalf("profile %q must be rejected", bad)
		}
	}
	for _, ok := range []string{"work", "some_name", "a.b-c", "0shop"} {
		if a.cmdProfile([]string{"add", ok, "--url", "https://x.example.test"}) != 0 {
			t.Fatalf("profile %q must be accepted", ok)
		}
	}
}

func TestConfigDirHonorsXDG(t *testing.T) {
	env := map[string]string{}
	a, _, _ := testApp(t, env)
	if got, want := a.configDir(), filepath.Join(a.home, ".config", "kuukura"); got != want {
		t.Fatalf("default: %s", got)
	}
	elsewhere := t.TempDir() // absolute on every OS
	env["XDG_CONFIG_HOME"] = elsewhere
	if got := a.configDir(); got != filepath.Join(elsewhere, "kuukura") {
		t.Fatalf("XDG_CONFIG_HOME: %s", got)
	}
	env["XDG_CONFIG_HOME"] = "relative/path" // not absolute: ignored, never guessed
	if got, want := a.configDir(), filepath.Join(a.home, ".config", "kuukura"); got != want {
		t.Fatalf("relative XDG_CONFIG_HOME must be ignored: %s", got)
	}
	// a profile written with XDG set lands there, not under HOME
	env["XDG_CONFIG_HOME"] = t.TempDir()
	if a.cmdProfile([]string{"add", "work", "--url", "https://work.example.test"}) != 0 {
		t.Fatal("add")
	}
	if _, err := readFile(filepath.Join(env["XDG_CONFIG_HOME"], "kuukura", "config.toml")); err != nil {
		t.Fatal("config must be written under XDG_CONFIG_HOME")
	}
	if _, err := readFile(filepath.Join(a.home, ".config", "kuukura", "config.toml")); err == nil {
		t.Fatal("nothing may be written under HOME when XDG_CONFIG_HOME is set")
	}
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

// On a machine without a keychain (a server, a container, WSL) the whole flow still works: login saves the session
// to a private file, commands read it, and removing the profile deletes it. The token never enters config.toml.
func TestLoginWithoutAKeychainUsesAPrivateFile(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w := newWorld(t, p)
		w.admin()
		cfg := filepath.Join(w.home, ".config", "kuukura")
		var warned []string
		w.altStore = newSessionStore(nil, cfg, func(m string) { warned = append(warned, m) })

		mustOK(t, w.ku("", false, nil, "profile", "add", "default", "--url", w.srv.URL))
		r := w.ku("", false, nil, "login")
		if r.code != 0 || r.out != "" || !strings.Contains(r.errOut, "✓ Signed in to default") {
			t.Fatalf("login: %q %q", r.out, r.errOut)
		}
		file := filepath.Join(cfg, "sessions", "default")
		tok, err := readFile(file)
		if err != nil || !strings.HasPrefix(tok, "ku_") {
			t.Fatalf("the session must be in the private file: %v", err)
		}
		if len(warned) != 1 || !strings.Contains(warned[0], file) {
			t.Fatalf("one warning naming the file: %v", warned)
		}
		if conf, _ := readFile(filepath.Join(cfg, "config.toml")); strings.Contains(conf, tok) {
			t.Fatal("the token must never be in config.toml")
		}
		if r := w.ku("", false, nil, "secret", "list"); r.code != 0 {
			t.Fatalf("commands read the session from the file: %q", r.errOut)
		}
		mustOK(t, w.ku("", false, nil, "profile", "remove", "default"))
		if _, err := readFile(file); err == nil {
			t.Fatal("removing the profile must delete its session file")
		}
	})
}

func TestLoginFlow(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w := newWorld(t, p)
		w.admin() // enrolled admin with a passkey
		// no profile yet: login explains what to do first
		if r := w.ku("", false, nil, "login"); r.code != 1 || !strings.Contains(r.errOut, "ku profile add <name> --url") {
			t.Fatalf("login without a profile: %q", r.errOut)
		}
		mustOK(t, w.ku("", false, nil, "profile", "add", "default", "--url", w.srv.URL))
		// the server URL belongs to the profile; with one in place, --url is the only thing wrong here
		if r := w.ku("", false, nil, "login", "--url", w.srv.URL); r.code != 2 || r.errOut != "Usage: ku login [--profile <name>]\n" {
			t.Fatalf("login does not take --url: %q", r.errOut)
		}
		r := w.ku("", false, nil, "login")
		if r.code != 0 || r.out != "" || !strings.Contains(r.errOut, "✓ Signed in to default") {
			t.Fatalf("login: %q %q", r.out, r.errOut)
		}
		if !strings.Contains(r.errOut, "copy this link:\n  "+w.srv.URL+"/auth/login?") || !strings.Contains(r.errOut, "cli_profile=default") {
			t.Fatalf("login must print the sign-in link so it can be copied: %q", r.errOut)
		}
		tok, err := w.store.Get("default")
		if err != nil || !strings.HasPrefix(tok, "ku_") {
			t.Fatal("the token goes to the session store")
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

// callback hits the CLI's local sign-in port the way the browser's redirect does.
func callback(t *testing.T, loginURL, query string) (int, string) {
	t.Helper()
	u, err := url.Parse(loginURL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get("http://127.0.0.1:" + u.Query().Get("cli_port") + "/callback" + query)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// Only a callback with the state the CLI made and a code signs in; anything else is ignored and saves nothing.
func TestLoginCallbackNeedsTheStateAndACode(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w := newWorld(t, p)
		w.admin()
		mustOK(t, w.ku("", false, nil, "profile", "add", "default", "--url", w.srv.URL))
		w.opener = func(raw string) error {
			state := mustParse(t, raw).Query().Get("cli_state")
			for _, q := range []string{"?state=wrong&code=c", "?state=" + state, "?state=" + state + "&code=", "?code=c", ""} {
				if code, _ := callback(t, raw, q); code != 404 {
					t.Errorf("callback %q: %d, want 404", q, code)
				}
			}
			if _, err := w.store.Get("default"); !errors.Is(err, errNoToken) {
				t.Errorf("a bad callback must save nothing: %v", err)
			}
			return w.browser(raw) // the real sign-in still works afterwards
		}
		mustOK(t, w.ku("", false, nil, "login"))
		if tok, err := w.store.Get("default"); err != nil || !strings.HasPrefix(tok, "ku_") {
			t.Fatalf("the right callback signs in: %v", err)
		}
	})
}

// If the code cannot be exchanged the browser says so, the terminal says so, and nothing is saved.
func TestLoginFailsWhenTheTokenExchangeFails(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w := newWorld(t, p)
		w.admin()
		mustOK(t, w.ku("", false, nil, "profile", "add", "default", "--url", w.srv.URL))
		var page string
		w.opener = func(raw string) error {
			var code int
			code, page = callback(t, raw, "?state="+mustParse(t, raw).Query().Get("cli_state")+"&code=not-a-real-code")
			if code != 200 {
				t.Errorf("the page still loads: %d", code)
			}
			return nil
		}
		r := w.ku("", false, nil, "login")
		if r.code != 1 || !strings.Contains(r.errOut, "✗ Sign-in failed.\n  Run: ku login\n") || r.out != "" {
			t.Fatalf("login: %d %q %q", r.code, r.out, r.errOut)
		}
		if !strings.Contains(page, "Sign-in did not finish") || strings.Contains(page, "You're signed in") {
			t.Fatalf("the browser must not claim success: %q", page)
		}
		if _, err := w.store.Get("default"); !errors.Is(err, errNoToken) {
			t.Fatalf("nothing is saved: %v", err)
		}
	})
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
