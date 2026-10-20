package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	profileVerbs = "ku profile add|use|list|remove"
	profileAdd   = "ku profile add <name> --url <url>"
)

func (a *app) cmdProfile(args []string) int {
	if len(args) == 0 {
		return a.usageFail(profileVerbs)
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return a.fail("%v", err)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		p, ok := a.parse(profileAdd, rest, []string{"url"})
		if !ok {
			return exitUsage
		}
		if len(p.pos) != 1 || p.flags["url"] == "" {
			return a.usageFail(profileAdd)
		}
		name := p.pos[0]
		if !profileRE.MatchString(name) {
			return a.argFail("Profile names use a-z, 0-9, dot, dash and underscore")
		}
		u, err := validateURL(p.flags["url"])
		if err != nil {
			return a.argFail("%v", err)
		}
		if _, exists := cfg.Profiles[name]; exists {
			return a.fail("Profile %s already exists.", name)
		}
		cfg.Profiles[name] = profileCfg{URL: u}
		if cfg.Active == "" {
			cfg.Active = name
		}
		if err := a.saveConfig(cfg); err != nil {
			return a.fail("%v", err)
		}
		a.say("✓ Added profile %s", name)
	case "use":
		if len(rest) != 1 {
			return a.usageFail("ku profile use <name>")
		}
		if _, ok := cfg.Profiles[rest[0]]; !ok {
			return a.failNext("ku profile list", "Unknown profile %s", rest[0])
		}
		cfg.Active = rest[0]
		if err := a.saveConfig(cfg); err != nil {
			return a.fail("%v", err)
		}
		a.say("✓ Using profile %s", rest[0])
	case "list":
		for _, n := range sortedKeys(cfg.Profiles) {
			mark := " "
			if n == cfg.Active {
				mark = "*"
			}
			fmt.Fprintf(a.out, "%s %s  %s\n", mark, n, cfg.Profiles[n].URL)
		}
	case "remove":
		if len(rest) != 1 {
			return a.usageFail("ku profile remove <name>")
		}
		name := rest[0]
		if _, ok := cfg.Profiles[name]; !ok {
			return a.failNext("ku profile list", "Unknown profile %s", name)
		}
		if err := a.store.Delete(name); err != nil {
			return a.fail("Could not remove the saved session: %v", err)
		}
		delete(cfg.Profiles, name)
		if cfg.Active == name {
			cfg.Active = ""
		}
		if err := a.saveConfig(cfg); err != nil {
			return a.fail("%v", err)
		}
		a.say("✓ Removed profile %s", name)
	default:
		return a.usageFail(profileVerbs)
	}
	return 0
}

// cmdLink links the current folder to an app (local alias only; nothing in the repo or on the server).
func (a *app) cmdLink(args []string) int {
	const linkUsage = "ku link [<app>] [--profile <name>]"
	p, ok := a.parse(linkUsage, args, []string{"profile"})
	if !ok {
		return exitUsage
	}
	if len(p.pos) > 1 {
		return a.usageFail(linkUsage)
	}
	if len(p.pos) == 0 {
		l, ok, err := a.currentLink(a.cwd)
		if err != nil {
			return a.fail("%v", err)
		}
		if !ok {
			return a.failNext("ku link <app>", "This folder is not linked to an app")
		}
		fmt.Fprintf(a.out, "This folder is linked to %s\n", l.App)
		return 0
	}
	app := strings.ToLower(p.pos[0])
	if !tagPartRE.MatchString(app) {
		return a.argFail("App names use a-z, 0-9, dot, dash and underscore")
	}
	l := link{App: app, Profile: p.flags["profile"]}
	if l.Profile != "" {
		cfg, err := a.loadConfig()
		if err != nil {
			return a.fail("%v", err)
		}
		if _, ok := cfg.Profiles[l.Profile]; !ok {
			return a.failNext("ku profile list", "Unknown profile %s", l.Profile)
		}
	}
	links, err := a.loadLinks()
	if err != nil {
		return a.fail("%v", err)
	}
	links[filepath.Clean(a.cwd)] = l
	if err := a.saveLinks(links); err != nil {
		return a.fail("%v", err)
	}
	a.say("✓ Linked this folder to %s", app)
	return 0
}

// cmdLogin signs in through the browser with a localhost PKCE callback and saves the token (keychain or private file).
func (a *app) cmdLogin(args []string) int {
	const loginUsage = "ku login [--profile <name>]"
	p, ok := a.parse(loginUsage, args, []string{"profile"})
	if !ok {
		return exitUsage
	}
	if len(p.pos) != 0 {
		return a.usageFail(loginUsage)
	}
	if a.getenv("KU_URL") != "" || a.getenv("KU_TOKEN") != "" {
		return a.fail("KU_URL or KU_TOKEN is set, so there is nothing to log in to. Unset it to sign in with a profile")
	}
	// The server URL lives in the profile: add one first with `ku profile add <name> --url <url>`.
	pr, err := a.resolve(p.flags["profile"])
	if err != nil {
		return a.fail("%v", err)
	}
	a.say("profile: %s", pr.name)

	verifier := randomString(32)
	state := randomString(16)
	sum := sha256.Sum256([]byte(verifier))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return a.fail("Could not open a local port for the sign-in.")
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	c := &client{a: a, base: pr.url}
	// signIn trades the one-time code for the token and saves it, so the page can say what really happened.
	// It returns what went wrong, or "".
	signIn := func(code string) string {
		var tok struct {
			Token string `json:"token"`
		}
		if err := c.call("POST", "/auth/token", map[string]string{"code": code, "verifier": verifier}, &tok); err != nil {
			return "Sign-in failed"
		}
		if err := a.store.Set(pr.name, tok.Token); err != nil {
			return fmt.Sprintf("Could not save the session: %v", err)
		}
		return ""
	}
	got := make(chan string, 1)
	var claimed atomic.Bool // only the first callback signs in
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if r.URL.Path != "/callback" || r.URL.Query().Get("state") != state || code == "" || !claimed.CompareAndSwap(false, true) {
			http.NotFound(w, r)
			return
		}
		failure := signIn(code)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		w.Header().Set("Cache-Control", "no-store")
		if failure != "" {
			fmt.Fprint(w, signInFailedPage(pr.name))
		} else {
			fmt.Fprint(w, signedInPage(pr.name))
		}
		got <- failure
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	q := url.Values{"cli_port": {strconv.Itoa(port)}, "cli_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "cli_state": {state}, "cli_profile": {pr.name}}
	loginURL := pr.url + "/auth/login?" + q.Encode()
	// Always print the link: the default browser may not be the one you want (another profile or account).
	a.say("Opening your browser to sign in. If it does not open, or you want another browser, copy this link:\n  %s", loginURL)
	_ = a.openURL(loginURL)
	select {
	case failure := <-got:
		if failure != "" {
			return a.failNext("ku login", "%s", failure)
		}
	case <-time.After(5 * time.Minute):
		return a.failNext("ku login", "Sign-in timed out")
	}
	a.say("✓ Signed in to %s", pr.name)
	return 0
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // never fails: the runtime aborts instead
	return base64.RawURLEncoding.EncodeToString(b)
}
