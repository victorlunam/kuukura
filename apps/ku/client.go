package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/victorlunam/kuukura/internal/cli"
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

// plain turns an error into short, non-technical copy. Every problem code the API can return has its own message
// here (a test walks api.Codes), so a code added there cannot fall through to the generic one by accident. The
// server's detail is used where it says something the code does not; it never carries a secret value.
func plain(err error) string {
	var p *problem
	if !errors.As(err, &p) {
		return err.Error()
	}
	detail := func(fallback string) string {
		if p.Detail != "" {
			return cli.Sentence(p.Detail)
		}
		return fallback
	}
	switch p.Code {
	case "unauthorized":
		return "Your session ended."
	case "forbidden":
		return "You don't have access to that."
	case "quota-exceeded":
		if p.retryAfter != "" {
			return "Too many requests. Try again in " + p.retryAfter + " seconds."
		}
		return "Too many requests. Try again in a moment."
	case "not-found":
		return detail("No matching secret.")
	case "step-up-required":
		return "This needs a confirmation with your passkey or authenticator app."
	case "factor-required":
		return "Your account has no passkey or authenticator app to confirm with. Ask your admin for a new invite."
	case "confirmation-expired":
		return "The confirmation expired. Run the command again."
	case "https-required":
		return "The server must be reached over https."
	case "invalid-request":
		return detail("The server did not accept that request.")
	case "needs-one":
		return detail("Pick exactly one secret.")
	case "conflict":
		return detail("That already exists.")
	case "last-admin":
		return detail("That is the last admin.")
	case "last-factor":
		return detail("This is your only passkey or authenticator app.")
	case "kind-mismatch":
		return detail("That secret holds a different kind of value.")
	case "ambiguous":
		return "More than one secret matches. Add a tag to pick one."
	case "blocked":
		return "That secret is blocked until you save a new value."
	case "clash":
		return "A secret with that name and those tags already exists."
	case "needs-confirmation":
		return "That secret does not exist yet."
	case "method-not-allowed", "too-large":
		return "The server did not understand that request. Update ku and try again."
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
			return nil, p, &nextStep{"You are not logged in.", "ku login"}
		case err != nil: // an unreadable session is not a missing one: say what is wrong
			return nil, p, fmt.Errorf("cannot read the saved session: %w", err)
		}
		p.token = tok
	}
	return &client{a: a, base: p.url, token: p.token, profile: p.name}, p, nil
}
