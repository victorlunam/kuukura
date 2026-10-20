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
	"strconv"
	"sync/atomic"
	"time"

	"github.com/victorlunam/kuukura/internal/cli"
)

// cmdLogin signs in through the browser with a localhost PKCE callback and saves the token (keychain or private file).
func (a *app) cmdLogin(args []string) int {
	const loginUsage = "ku login [--profile <name>]"
	p, ok := a.parse(loginUsage, args, []string{"profile"})
	if !ok {
		return cli.ExitUsage
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
