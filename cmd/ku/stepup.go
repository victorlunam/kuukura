package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"time"
)

// subjectOf is the canonical selector string a step-up is bound to (matches the server).
func subjectOf(name string, tags []string) string {
	t := make([]string, len(tags))
	for i, x := range tags {
		t[i] = strings.ToLower(x)
	}
	slices.Sort(t)
	return strings.TrimSpace(strings.ToUpper(name) + " " + strings.Join(slices.Compact(t), " "))
}

var errTimeout = errors.New("timed out")

// waitFor calls check every a.poll until it reports done, fails, or the timeout passes (errTimeout).
func (a *app) waitFor(timeout time.Duration, check func() (bool, error)) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	tick := time.NewTicker(a.poll)
	defer tick.Stop()
	for {
		if done, err := check(); done || err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return errTimeout
		case <-tick.C:
		}
	}
}

// openLink opens a link the server returned only if it points at the profile's own server. Whatever else the
// server says (a file: path, a UNC share, another host) is a program or a phishing page the OS would happily
// launch on the user's behalf, so it is only shown.
func (a *app) openLink(c *client, raw string) {
	u, uerr := url.Parse(raw)
	base, berr := url.Parse(c.base)
	if uerr == nil && berr == nil && u.Scheme == base.Scheme && strings.EqualFold(u.Host, base.Host) {
		_ = a.openURL(raw)
		return
	}
	a.say("Not opened: this link does not point at %s.", c.base)
}

// passkeyLabel names a passkey the way the OS shows it, where one OS is clear enough to do so.
func passkeyLabel(goos string) string {
	if goos == "darwin" {
		return "Touch ID"
	}
	return "your passkey"
}

// stepUp runs a confirmation with the account's own second step: the server issues a one-time request, the
// browser page asks for a passkey or an authenticator code, and the CLI waits.
// Returns the grant id for X-Step-Up.
func (a *app) stepUp(c *client, purpose, subject string) (string, error) {
	var r struct {
		ID      string   `json:"id"`
		URL     string   `json:"url"`
		Methods []string `json:"methods"`
	}
	if err := c.call("POST", "/auth/stepup", map[string]string{"purpose": purpose, "subject": subject, "profile": c.profile}, &r); err != nil {
		return "", err
	}
	fmt.Fprintf(a.err, "If the browser does not open, copy this link:\n  %s\n", r.URL)
	a.openLink(c, r.URL)
	if len(r.Methods) == 1 && r.Methods[0] == "passkey" {
		fmt.Fprintf(a.err, "Confirm with %s...", passkeyLabel(runtime.GOOS)) // a passkey is the only way, so name it
	} else {
		fmt.Fprint(a.err, "Confirm in your browser...")
	}
	err := a.waitFor(2*time.Minute, func() (bool, error) {
		var s struct {
			Done bool `json:"done"`
		}
		err := c.call("GET", "/auth/stepup/"+r.ID, nil, &s)
		return s.Done, err
	})
	if err != nil {
		fmt.Fprintln(a.err)
		if errors.Is(err, errTimeout) {
			return "", errors.New("the confirmation timed out")
		}
		return "", err
	}
	fmt.Fprintln(a.err, " ✓")
	return r.ID, nil
}

// callStepUp calls the API, and if it asks for a confirmation, does it once and retries.
func (a *app) callStepUp(c *client, purpose, subject, method, path string, body, out any) error {
	err := c.call(method, path, body, out)
	var p *problem
	if !errors.As(err, &p) || p.Code != "step-up-required" {
		return err
	}
	id, err := a.stepUp(c, purpose, subject)
	if err != nil {
		return err
	}
	return c.call(method, path, body, out, "X-Step-Up", id)
}
