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
	"time"
)

func (a *app) cmdProfile(args []string) int {
	if len(args) == 0 {
		return a.fail("Use: ku profile add|use|list|remove")
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return a.fail("%v", err)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		p, err := parseArgs(rest, "url")
		if err != nil || len(p.pos) != 1 || p.flags["url"] == "" {
			return a.fail("Use: ku profile add <name> --url <url>")
		}
		name := p.pos[0]
		if !profileRE.MatchString(name) {
			return a.fail("Profile names use a-z, 0-9, dot, dash and underscore.")
		}
		u, err := validateURL(p.flags["url"])
		if err != nil {
			return a.fail("%v.", err)
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
		fmt.Fprintf(a.out, "✓ Added profile %s\n", name)
	case "use":
		if len(rest) != 1 {
			return a.fail("Use: ku profile use <name>")
		}
		if _, ok := cfg.Profiles[rest[0]]; !ok {
			return a.fail("Unknown profile %s.", rest[0])
		}
		cfg.Active = rest[0]
		if err := a.saveConfig(cfg); err != nil {
			return a.fail("%v", err)
		}
		fmt.Fprintf(a.out, "✓ Using profile %s\n", rest[0])
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
			return a.fail("Use: ku profile remove <name>")
		}
		name := rest[0]
		if _, ok := cfg.Profiles[name]; !ok {
			return a.fail("Unknown profile %s.", name)
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
		fmt.Fprintf(a.out, "✓ Removed profile %s\n", name)
	default:
		return a.fail("Use: ku profile add|use|list|remove")
	}
	return 0
}

// cmdLink links the current folder to an app (local alias only; nothing in the repo or on the server).
func (a *app) cmdLink(args []string) int {
	p, err := parseArgs(args, "profile")
	if err != nil || len(p.pos) > 1 {
		return a.fail("Use: ku link <app> [--profile <name>]")
	}
	if len(p.pos) == 0 {
		l, ok, err := a.currentLink(a.cwd)
		if err != nil {
			return a.fail("%v", err)
		}
		if !ok {
			return a.fail("This folder is not linked to an app. Run: ku link <app>")
		}
		fmt.Fprintf(a.out, "This folder is linked to %s\n", l.App)
		return 0
	}
	app := strings.ToLower(p.pos[0])
	if !tagPartRE.MatchString(app) {
		return a.fail("App names use a-z, 0-9, dot, dash and underscore.")
	}
	l := link{App: app, Profile: p.flags["profile"]}
	if l.Profile != "" {
		cfg, err := a.loadConfig()
		if err != nil {
			return a.fail("%v", err)
		}
		if _, ok := cfg.Profiles[l.Profile]; !ok {
			return a.fail("Unknown profile %s.", l.Profile)
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
	fmt.Fprintf(a.out, "✓ Linked this folder to %s\n", app)
	return 0
}

// cmdLogin signs in through the browser with a localhost PKCE callback and stores the token in the Keychain.
func (a *app) cmdLogin(args []string) int {
	p, err := parseArgs(args, "url", "profile")
	if err != nil || len(p.pos) != 0 {
		return a.fail("Use: ku login [--url <url>]")
	}
	if a.getenv("KU_URL") != "" || a.getenv("KU_TOKEN") != "" {
		return a.fail("KU_URL and KU_TOKEN are set, so there is nothing to log in to.")
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return a.fail("%v", err)
	}
	if u := p.flags["url"]; u != "" {
		if len(cfg.Profiles) > 0 {
			return a.fail("You already have profiles. Add this one with: ku profile add <name> --url %s", u)
		}
		clean, err := validateURL(u)
		if err != nil {
			return a.fail("%v.", err)
		}
		cfg.Profiles["default"], cfg.Active = profileCfg{URL: clean}, "default"
		if err := a.saveConfig(cfg); err != nil {
			return a.fail("%v", err)
		}
	}
	pr, err := a.resolve(p.flags["profile"])
	if err != nil {
		return a.fail("%v.", err)
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
	type result struct{ code string }
	got := make(chan result, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" || r.URL.Query().Get("state") != state || r.URL.Query().Get("code") == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "You are signed in. You can close this tab.")
		select {
		case got <- result{r.URL.Query().Get("code")}:
		default:
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	q := url.Values{"cli_port": {strconv.Itoa(port)}, "cli_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "cli_state": {state}}
	loginURL := pr.url + "/auth/login?" + q.Encode()
	a.say("Opening your browser to sign in...")
	if err := a.openURL(loginURL); err != nil {
		a.say("Open this link to sign in:\n  %s", loginURL)
	}
	var res result
	select {
	case res = <-got:
	case <-time.After(5 * time.Minute):
		return a.fail("Sign-in timed out. Try again: ku login")
	}
	c := &client{a: a, base: pr.url}
	var tok struct {
		Token string `json:"token"`
	}
	if err := c.call("POST", "/auth/token", map[string]string{"code": res.code, "verifier": verifier}, &tok); err != nil {
		return a.fail("Sign-in failed. Try again: ku login")
	}
	if err := a.store.Set(pr.name, tok.Token); err != nil {
		return a.fail("Could not save the session: %v", err)
	}
	fmt.Fprintf(a.out, "✓ Signed in to %s\n", pr.name)
	return 0
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
