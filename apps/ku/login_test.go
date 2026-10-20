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
