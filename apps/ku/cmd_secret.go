package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/victorlunam/kuukura/internal/cli"
)

type secretRow struct {
	Name    string   `json:"name"`
	Version int      `json:"version"`
	Tags    []string `json:"tags"`
}

type valueResp struct {
	Name        string `json:"name"`
	Version     int    `json:"version"`
	Kind        string `json:"kind"`
	Filename    string `json:"filename"`
	Value       string `json:"value"`
	ValueBase64 string `json:"value_base64"`
}

func (v valueResp) bytes() ([]byte, error) {
	if v.Kind == "file" {
		return base64.StdEncoding.DecodeString(v.ValueBase64)
	}
	return []byte(v.Value), nil
}

const (
	secretVerbs  = "ku secret list|set|get|update|revoke|archive"
	listUsage    = "ku secret list [name] [tags]"
	setUsage     = "ku secret set <name> [tags] [--generate | --file <path>] [--yes]"
	getUsage     = "ku secret get <name> [tags] --reveal | --out <path>"
	updateUsage  = "ku secret update <name|tags> [--name <new>] [+tag -tag] [--authorize on|off] [--yes]"
	revokeUsage  = "ku secret revoke <name|tags> [--yes]"
	archiveUsage = "ku secret archive <name|tags> [--yes]"
)

func (a *app) cmdSecret(args []string) int {
	if len(args) == 0 {
		return a.usageFail(secretVerbs)
	}
	switch args[0] {
	case "list":
		return a.secretList(args[1:])
	case "set":
		return a.secretSet(args[1:])
	case "get":
		return a.secretGet(args[1:])
	case "update":
		return a.secretUpdate(args[1:])
	case "revoke":
		return a.secretBulk(args[1:], "revoke")
	case "archive":
		return a.secretBulk(args[1:], "archive")
	}
	return a.usageFail(secretVerbs)
}

func (a *app) listSecrets(c *client, name string, tags []string) ([]secretRow, error) {
	q := url.Values{"tags": {strings.Join(tags, ",")}}
	if name != "" {
		q.Set("name", name)
	}
	var r struct {
		Secrets []secretRow `json:"secrets"`
	}
	return r.Secrets, c.call("GET", "/secrets?"+q.Encode(), nil, &r)
}

// secretList shows name, version and tags. Never a value, not even masked.
func (a *app) secretList(args []string) int {
	p, ok := a.parse(listUsage, args, []string{"profile"})
	if !ok {
		return cli.ExitUsage
	}
	name, tags, err := selectorFrom(p.pos)
	if err != nil {
		return a.argFail("%v", err)
	}
	c, _, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v", err)
	}
	rows, err := a.listSecrets(c, name, tags)
	if err != nil {
		return a.report(err, func(t string) string { return "ku secret list " + t })
	}
	if len(rows) == 0 {
		a.say("No secrets found.")
		return 0
	}
	w := 18
	for _, r := range rows {
		w = max(w, len(r.Name)+2)
	}
	fmt.Fprintf(a.out, "%-*s%-9s%s\n", w, "NAME", "VERSION", "TAGS")
	for _, r := range rows {
		fmt.Fprintf(a.out, "%-*s%-9d%s\n", w, r.Name, r.Version, strings.Join(r.Tags, " "))
	}
	return 0
}

// secretSet reads the value from a hidden prompt, stdin (no terminal), --generate or --file. Never an argument.
func (a *app) secretSet(args []string) int {
	p, ok := a.parse(setUsage, args, []string{"file", "profile"}, "generate", "yes")
	if !ok {
		return cli.ExitUsage
	}
	name, tags, err := selectorFrom(p.pos)
	if err != nil {
		return a.argFail("%v", err)
	}
	if name == "" || p.has("generate") && p.has("file") {
		return a.usageFail(setUsage)
	}
	body := map[string]any{"name": name, "tags": nonNilTags(tags)}
	switch {
	case p.has("generate"):
		body["generate"] = true
	case p.has("file"):
		path := p.flags["file"]
		st, err := os.Stat(path)
		if err != nil || !st.Mode().IsRegular() {
			return a.fail("Cannot read that file")
		}
		if st.Size() > 1<<20 {
			return a.fail("Files can be at most 1 MB")
		}
		data, err := os.ReadFile(path) // #nosec G304 -- the user chose this path
		if err != nil {
			return a.fail("Cannot read that file")
		}
		body["kind"], body["filename"], body["value_base64"] = "file", filepath.Base(path), base64.StdEncoding.EncodeToString(data)
	default:
		val, err := a.readValue()
		if err != nil {
			return a.fail("%v", err)
		}
		body["value"] = val
	}
	c, _, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v", err)
	}
	var res struct {
		Name    string `json:"name"`
		Version int    `json:"version"`
	}
	err = c.call("POST", "/secrets/versions", body, &res)
	var pr *problem
	if errors.As(err, &pr) && pr.Code == "needs-confirmation" {
		ok, cerr := a.confirm(name+" is new. Create it?", p.has("yes"))
		if cerr != nil {
			return a.fail("%s is new, and there is no terminal to ask: %v", name, cerr)
		}
		if !ok {
			return a.fail("Nothing saved")
		}
		body["create"] = true
		err = c.call("POST", "/secrets/versions", body, &res)
	}
	if err != nil {
		return a.report(err, func(t string) string { return "ku secret set " + name + " " + t })
	}
	a.say("✓ Saved %s (version %d)", res.Name, res.Version)
	if p.has("generate") {
		a.say("  A random value was created on the server. It is not shown.")
	}
	return 0
}

func nonNilTags(t []string) []string {
	if t == nil {
		return []string{}
	}
	return t
}

func (a *app) readValue() (string, error) {
	var val string
	if a.isTTY {
		v, err := a.readSecret("Value (hidden):")
		if err != nil {
			return "", err
		}
		val = v
	} else {
		b, err := io.ReadAll(io.LimitReader(a.in, 64<<10+2))
		if err != nil {
			return "", errors.New("cannot read the value")
		}
		val = strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	}
	if val == "" {
		return "", errors.New("the value is empty")
	}
	if len(val) > 64<<10 {
		return "", errors.New("text values can be at most 64 KB. Use --file for larger ones")
	}
	return val, nil
}

// secretGet needs --reveal or --out, and always a confirmation with the account's passkey or authenticator app.
func (a *app) secretGet(args []string) int {
	p, ok := a.parse(getUsage, args, []string{"out", "profile"}, "reveal")
	if !ok {
		return cli.ExitUsage
	}
	name, tags, err := selectorFrom(p.pos)
	if err != nil {
		return a.argFail("%v", err)
	}
	if name == "" && len(tags) == 0 || p.has("reveal") == p.has("out") {
		return a.usageFail(getUsage)
	}
	c, _, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v", err)
	}
	var v valueResp
	if err := a.callStepUp(c, "reveal", subjectOf(name, tags), "POST", "/secrets/reveal", selReq{name, nonNilTags(tags)}, &v); err != nil {
		return a.report(err, func(t string) string {
			return joinWords("ku secret get", name, t, "--reveal")
		})
	}
	data, err := v.bytes()
	if err != nil {
		return a.fail("The server sent something unreadable.")
	}
	if p.has("out") {
		if err := writePrivate(p.flags["out"], data); err != nil {
			return a.fail("Cannot write that file")
		}
		a.say("✓ Saved to %s", p.flags["out"])
		return 0
	}
	if _, err := a.out.Write(data); err != nil {
		return 1
	}
	if v.Kind != "file" && a.isTTY {
		fmt.Fprintln(a.out)
	}
	return 0
}
