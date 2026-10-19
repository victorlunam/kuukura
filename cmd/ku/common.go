package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type selReq struct {
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags"`
}

// subjectOf is the canonical selector string a step-up is bound to (matches the server).
func subjectOf(name string, tags []string) string {
	t := make([]string, 0, len(tags))
	seen := map[string]bool{}
	for _, x := range tags {
		x = strings.ToLower(x)
		if !seen[x] {
			seen[x] = true
			t = append(t, x)
		}
	}
	sort.Strings(t)
	return strings.TrimSpace(strings.ToUpper(name) + " " + strings.Join(t, " "))
}

var stdinReader *bufio.Reader

func (a *app) stdin() *bufio.Reader {
	if stdinReader == nil {
		stdinReader = bufio.NewReader(a.in)
	}
	return stdinReader
}

// confirm asks a y/N question. --yes skips it; without a terminal it refuses rather than guessing.
func (a *app) confirm(question string, yes bool) (bool, error) {
	if yes {
		return true, nil
	}
	if !a.isTTY {
		return false, errors.New("add --yes to confirm when there is no terminal")
	}
	fmt.Fprintf(a.err, "%s (y/N) ", question)
	line, _ := a.stdin().ReadString('\n')
	l := strings.ToLower(strings.TrimSpace(line))
	return l == "y" || l == "yes", nil
}

// stepUp runs a confirmation with the account's own second step: the server issues a one-time request, the
// browser page asks for a passkey (Touch ID) or an authenticator code, and the CLI waits.
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
	if len(r.Methods) == 1 && r.Methods[0] == "passkey" {
		fmt.Fprint(a.err, "Confirm with Touch ID...") // a passkey is the only way, so name it
	} else {
		fmt.Fprint(a.err, "Confirm in your browser...")
	}
	_ = a.openURL(r.URL)
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		var s struct {
			Done bool `json:"done"`
		}
		if err := c.call("GET", "/auth/stepup/"+r.ID, nil, &s); err != nil {
			fmt.Fprintln(a.err)
			return "", err
		}
		if s.Done {
			fmt.Fprintln(a.err, " ✓")
			return r.ID, nil
		}
		time.Sleep(a.poll)
	}
	fmt.Fprintln(a.err)
	return "", errors.New("the confirmation timed out")
}

// callStepUp calls the API, and if it asks for a Touch ID confirmation, does it once and retries.
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

func splitItem(item string) (name string, tags []string) {
	f := strings.Fields(item)
	if len(f) == 0 {
		return "", nil
	}
	return f[0], f[1:]
}

// itemLines renders "NAME  tag tag" rows with aligned names.
func itemLines(items []string, indent string) string {
	w := 0
	for _, it := range items {
		n, _ := splitItem(it)
		w = max(w, len(n))
	}
	var b strings.Builder
	for _, it := range items {
		n, t := splitItem(it)
		fmt.Fprintf(&b, "%s%-*s  %s\n", indent, w, n, strings.Join(t, " "))
	}
	return strings.TrimRight(b.String(), "\n")
}

// distinguishingTag finds a tag of the first item that not every item has, to suggest in a hint.
func distinguishingTag(items []string) string {
	if len(items) < 2 {
		return "key:value"
	}
	_, first := splitItem(items[0])
	for _, t := range first {
		all := true
		for _, it := range items[1:] {
			_, ts := splitItem(it)
			has := false
			for _, x := range ts {
				has = has || x == t
			}
			all = all && has
		}
		if !all {
			return t
		}
	}
	return "key:value"
}

// report prints an error in plain copy and returns exit code 1. hint builds the suggestion line for an
// ambiguous selection from a distinguishing tag.
func (a *app) report(err error, hint func(tag string) string) int {
	var p *problem
	if !errors.As(err, &p) {
		return a.fail("%s", plain(err))
	}
	switch p.Code {
	case "ambiguous":
		name, same := "", true
		for i, it := range p.Items {
			n, _ := splitItem(it)
			if i == 0 {
				name = n
			}
			same = same && n == name
		}
		if same && name != "" {
			a.fail("%d secrets are called %s:", len(p.Items), name)
		} else {
			a.fail("%d secrets match:", len(p.Items))
		}
		fmt.Fprintln(a.err, itemLines(p.Items, "    "))
		fmt.Fprintf(a.err, "  Add or remove a tag to pick one, for example: %s\n", hint(distinguishingTag(p.Items)))
		return 1
	case "blocked":
		for _, it := range p.Items {
			n, t := splitItem(it)
			a.fail("%s is blocked. Save a new value: ku secret set %s", n, strings.TrimSpace(n+" "+strings.Join(t, " ")))
		}
		return 1
	case "forbidden":
		if len(p.Items) > 0 {
			a.fail("You don't have access to:")
			fmt.Fprintln(a.err, itemLines(p.Items, "    "))
			return 1
		}
	}
	return a.fail("%s", plain(err))
}

func writePrivate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the user chose this path
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
