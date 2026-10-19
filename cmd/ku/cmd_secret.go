package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type secretRow struct {
	Name              string   `json:"name"`
	Version           int      `json:"version"`
	Tags              []string `json:"tags"`
	Kind              string   `json:"kind"`
	RequiresAuthorize bool     `json:"requires_authorize"`
	Blocked           bool     `json:"blocked"`
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

func (a *app) cmdSecret(args []string) int {
	if len(args) == 0 {
		return a.fail("Use: ku secret list|set|get|update|revoke|archive")
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
	return a.fail("Use: ku secret list|set|get|update|revoke|archive")
}

func (a *app) listSecrets(c *client, name string, tags []string) ([]secretRow, error) {
	path := "/secrets?tags=" + strings.Join(tags, ",")
	if name != "" {
		path += "&name=" + name
	}
	var r struct {
		Secrets []secretRow `json:"secrets"`
	}
	return r.Secrets, c.call("GET", path, nil, &r)
}

// secretList shows name, version and tags. Never a value, not even masked.
func (a *app) secretList(args []string) int {
	p, err := parseArgs(args, "profile")
	if err != nil {
		return a.fail("%v", err)
	}
	name, tags, err := selectorFrom(p.pos)
	if err != nil {
		return a.fail("%v.", err)
	}
	c, _, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v.", err)
	}
	rows, err := a.listSecrets(c, name, tags)
	if err != nil {
		return a.report(err, func(t string) string { return "ku secret list " + t })
	}
	if len(rows) == 0 {
		fmt.Fprintln(a.out, "No secrets found.")
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
	p, err := parseArgs(args, "file", "profile")
	if err != nil {
		return a.fail("%v", err)
	}
	name, tags, err := selectorFrom(p.pos)
	if err != nil || name == "" {
		return a.fail("Use: ku secret set <name> [tags] [--generate | --file <path>]")
	}
	if p.has("generate") && p.has("file") {
		return a.fail("Use --generate or --file, not both.")
	}
	body := map[string]any{"name": name, "tags": nonNilTags(tags)}
	switch {
	case p.has("generate"):
		body["generate"] = true
	case p.has("file"):
		path := p.flags["file"]
		st, err := os.Stat(path)
		if err != nil || !st.Mode().IsRegular() {
			return a.fail("Cannot read %s.", path)
		}
		if st.Size() > 1<<20 {
			return a.fail("Files can be at most 1 MB.")
		}
		data, err := os.ReadFile(path) // #nosec G304 -- the user chose this path
		if err != nil {
			return a.fail("Cannot read %s.", path)
		}
		body["kind"], body["filename"], body["value_base64"] = "file", filepath.Base(path), base64.StdEncoding.EncodeToString(data)
	default:
		val, err := a.readValue()
		if err != nil {
			return a.fail("%v.", err)
		}
		body["value"] = val
	}
	c, _, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v.", err)
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
			return a.fail("%s is new. %v.", name, cerr)
		}
		if !ok {
			fmt.Fprintln(a.err, "Nothing saved.")
			return 1
		}
		body["create"] = true
		err = c.call("POST", "/secrets/versions", body, &res)
	}
	if err != nil {
		return a.report(err, func(t string) string { return "ku secret set " + name + " " + t })
	}
	fmt.Fprintf(a.out, "✓ Saved %s (version %d)\n", res.Name, res.Version)
	if p.has("generate") {
		fmt.Fprintln(a.out, "  A random value was created on the server. It is not shown.")
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

// secretGet needs --reveal or --out, and always a Touch ID confirmation.
func (a *app) secretGet(args []string) int {
	p, err := parseArgs(args, "out", "profile")
	if err != nil {
		return a.fail("%v", err)
	}
	name, tags, err := selectorFrom(p.pos)
	if err != nil || name == "" && len(tags) == 0 {
		return a.fail("Use: ku secret get <name> [tags] --reveal | --out <path>")
	}
	if !p.has("reveal") && !p.has("out") {
		fmt.Fprintln(a.err, "Choose how to get it: --reveal or --out <file>")
		return 1
	}
	if p.has("reveal") && p.has("out") {
		return a.fail("Use --reveal or --out, not both.")
	}
	c, _, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v.", err)
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
			return a.fail("Cannot write %s.", p.flags["out"])
		}
		fmt.Fprintf(a.out, "✓ Saved to %s\n", p.flags["out"])
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

// splitUpdateArgs separates the selector from +tag / -tag changes.
func splitUpdateArgs(pos []string) (sel, add, rem []string, err error) {
	for _, t := range pos {
		switch {
		case strings.HasPrefix(t, "+"):
			add = append(add, strings.ToLower(t[1:]))
		case strings.HasPrefix(t, "-"):
			rem = append(rem, strings.ToLower(t[1:]))
		default:
			sel = append(sel, t)
		}
	}
	for _, t := range append(append([]string{}, add...), rem...) {
		if !strings.Contains(t, ":") {
			return nil, nil, nil, fmt.Errorf("%q is not a tag. Tags look like key:value", t)
		}
	}
	return
}

func (a *app) secretUpdate(args []string) int {
	p, err := parseArgs(args, "name", "authorize", "profile")
	if err != nil {
		return a.fail("%v", err)
	}
	selPos, add, rem, err := splitUpdateArgs(p.pos)
	if err != nil {
		return a.fail("%v.", err)
	}
	name, tags, err := selectorFrom(selPos)
	if err != nil || name == "" && len(tags) == 0 {
		return a.fail("Use: ku secret update <name|tags> [--name <new>] [+tag -tag] [--authorize on|off]")
	}
	body := map[string]any{"selector": selReq{name, nonNilTags(tags)}}
	if n := p.flags["name"]; n != "" {
		body["rename"] = strings.ToUpper(n)
	}
	if len(add) > 0 {
		body["add_tags"] = add
	}
	if len(rem) > 0 {
		body["remove_tags"] = rem
	}
	authorize := p.flags["authorize"]
	switch authorize {
	case "":
	case "on":
		body["requires_authorize"] = true
	case "off":
		body["requires_authorize"] = false
	default:
		return a.fail("--authorize takes on or off.")
	}
	if len(body) == 1 {
		return a.fail("Nothing to change. Use --name, +tag, -tag or --authorize.")
	}
	c, _, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v.", err)
	}
	rows, err := a.listSecrets(c, name, tags)
	if err != nil {
		return a.report(err, func(t string) string { return "ku secret update " + t })
	}
	if len(rows) == 0 {
		return a.fail("No matching secret.")
	}
	if p.flags["name"] != "" && len(rows) != 1 {
		return a.fail("--name works on exactly one secret. Add a tag to pick one.")
	}
	if n := len(rows); n > 1 {
		what := fmt.Sprintf("%d secrets will change.", n)
		switch authorize {
		case "on":
			what = fmt.Sprintf("%d secrets will ask Touch ID.", n)
		case "off":
			what = fmt.Sprintf("%d secrets will stop asking Touch ID.", n)
		}
		ok, cerr := a.confirm(what+" Continue?", p.has("yes"))
		if cerr != nil {
			return a.fail("%v.", cerr)
		}
		if !ok {
			fmt.Fprintln(a.err, "Nothing changed.")
			return 1
		}
	}
	var res struct {
		Updated []string `json:"updated"`
	}
	if authorize == "off" {
		err = a.callStepUp(c, "authorize_off", subjectOf(name, tags), "PATCH", "/secrets", body, &res)
	} else {
		err = c.call("PATCH", "/secrets", body, &res)
	}
	if err != nil {
		var pr *problem
		if errors.As(err, &pr) && pr.Code == "clash" {
			a.fail("%d of %d secrets would clash:", len(pr.Items), len(rows))
			for _, it := range pr.Items {
				fmt.Fprintf(a.err, "    %s already exists\n", it)
			}
			fmt.Fprintln(a.err, "  Nothing changed.")
			return 1
		}
		return a.report(err, func(t string) string { return "ku secret update " + t })
	}
	switch {
	case body["rename"] != nil && len(rows) == 1:
		fmt.Fprintf(a.out, "✓ Renamed %s to %s\n", rows[0].Name, body["rename"])
	case len(res.Updated) == 1:
		n, _ := splitItem(res.Updated[0])
		fmt.Fprintf(a.out, "✓ Updated %s\n", n)
	default:
		fmt.Fprintf(a.out, "✓ Updated %d secrets\n", len(res.Updated))
	}
	return 0
}

// secretBulk is revoke and archive: preview the list and confirm when several secrets are selected.
func (a *app) secretBulk(args []string, verb string) int {
	p, err := parseArgs(args, "profile")
	if err != nil {
		return a.fail("%v", err)
	}
	name, tags, err := selectorFrom(p.pos)
	if err != nil || name == "" && len(tags) == 0 {
		return a.fail("Use: ku secret %s <name|tags>", verb)
	}
	c, _, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v.", err)
	}
	rows, err := a.listSecrets(c, name, tags)
	if err != nil {
		return a.report(err, func(t string) string { return "ku secret " + verb + " " + t })
	}
	if len(rows) == 0 {
		return a.fail("No matching secret.")
	}
	if len(rows) > 1 {
		items := make([]string, len(rows))
		for i, r := range rows {
			items[i] = strings.TrimSpace(r.Name + " " + strings.Join(r.Tags, " "))
		}
		fmt.Fprintln(a.err, itemLines(items, "  "))
		past := map[string]string{"revoke": "revoked", "archive": "archived"}[verb]
		ok, cerr := a.confirm(fmt.Sprintf("%d secrets will be %s. Continue?", len(rows), past), p.has("yes"))
		if cerr != nil {
			return a.fail("%v.", cerr)
		}
		if !ok {
			fmt.Fprintln(a.err, "Nothing changed.")
			return 1
		}
	}
	sel := selReq{name, nonNilTags(tags)}
	var out struct {
		Revoked []string `json:"revoked"`
		Updated []string `json:"updated"`
	}
	if verb == "revoke" {
		err = c.call("POST", "/secrets/revoke", sel, &out)
	} else {
		err = c.call("PATCH", "/secrets", map[string]any{"selector": sel, "archived": true}, &out)
	}
	if err != nil {
		return a.report(err, func(t string) string { return "ku secret " + verb + " " + t })
	}
	n := len(rows)
	switch {
	case verb == "revoke" && n == 1:
		fmt.Fprintf(a.out, "✓ Revoked %s. It stays blocked until you save a new value.\n", rows[0].Name)
	case verb == "revoke":
		fmt.Fprintf(a.out, "✓ Revoked %d secrets. They stay blocked until you save new values.\n", n)
	case n == 1:
		fmt.Fprintf(a.out, "✓ Archived %s\n", rows[0].Name)
	default:
		fmt.Fprintf(a.out, "✓ Archived %d secrets\n", n)
	}
	return 0
}
