package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// client talks to exactly one server: the resolved profile's. Redirects are never followed
// (see app.http), so the token cannot travel anywhere else.
type client struct {
	a       *app
	base    string
	token   string
	profile string // shown on the server's confirmation pages (display only)
}

// problem is an RFC 9457 error from the server.
type problem struct {
	Code       string   `json:"code"`
	Detail     string   `json:"detail"`
	Items      []string `json:"items"`
	retryAfter string
}

func (p *problem) Error() string { return p.Code }

// call sends a JSON request and decodes a 2xx JSON response into out (may be nil).
func (c *client) call(method, path string, body, out any, hdr ...string) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.a.http.Do(req)
	if err != nil {
		return errors.New("cannot reach the server")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return errors.New("cannot reach the server")
	}
	if resp.StatusCode/100 != 2 {
		p := &problem{retryAfter: resp.Header.Get("Retry-After")}
		_ = json.Unmarshal(data, p)
		if p.Code == "" {
			p.Code = "internal"
		}
		return p
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// plain turns an error into short, non-technical copy.
func plain(err error) string {
	var p *problem
	if !errors.As(err, &p) {
		return err.Error()
	}
	switch p.Code {
	case "unauthorized":
		return "Your session ended. Run: ku login"
	case "forbidden":
		return "You don't have access to that."
	case "quota-exceeded":
		if p.retryAfter != "" {
			return "Too many requests. Try again in " + p.retryAfter + " seconds."
		}
		return "Too many requests. Try again in a moment."
	case "not-found":
		return "No matching secret."
	case "step-up-required":
		return "This needs a confirmation with your passkey or authenticator app."
	case "invalid-request", "needs-one", "conflict", "last-admin", "last-factor", "kind-mismatch":
		if p.Detail != "" {
			return strings.ToUpper(p.Detail[:1]) + p.Detail[1:] + "."
		}
	case "factor-required":
		return "Your account has no passkey or authenticator app to confirm with. Ask your admin for a new invite."
	case "https-required":
		return "The server must be reached over https."
	}
	return "Something went wrong on the server. Try again."
}

// withProfile resolves the profile, reads its token and returns a client. It prints the discreet profile line.
func (a *app) withProfile(flagProfile string, needToken bool) (*client, profile, error) {
	p, err := a.resolve(flagProfile)
	if err != nil {
		return nil, p, err
	}
	a.say("profile: %s", p.name)
	if needToken && p.token == "" {
		if p.ephemeral {
			return nil, p, errors.New("KU_URL is set but KU_TOKEN is not. Set KU_TOKEN to a machine token")
		}
		tok, err := a.store.Get(p.name)
		switch {
		case errors.Is(err, errNoToken) || err == nil && tok == "":
			return nil, p, errors.New("you are not logged in. Run: ku login")
		case err != nil: // an unreadable session is not a missing one: say what is wrong
			return nil, p, fmt.Errorf("cannot read the saved session: %w", err)
		}
		p.token = tok
	}
	return &client{a: a, base: p.url, token: p.token, profile: p.name}, p, nil
}
