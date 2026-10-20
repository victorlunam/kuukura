package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/victorlunam/kuukura/internal/cli"
)

// splitUpdateArgs separates the selector from +tag / -tag changes.
func splitUpdateArgs(pos []string) (sel, add, rem []string, err error) {
	for i, t := range pos {
		switch {
		case strings.HasPrefix(t, "+"), strings.HasPrefix(t, "-"):
			tag := strings.ToLower(t[1:])
			if !tagRE.MatchString(tag) {
				return nil, nil, nil, notATag(i + 1)
			}
			if t[0] == '+' {
				add = append(add, tag)
			} else {
				rem = append(rem, tag)
			}
		default:
			sel = append(sel, t)
		}
	}
	return
}

func (a *app) secretUpdate(args []string) int {
	p, ok := a.parse(updateUsage, args, []string{"name", "authorize", "profile"}, "yes")
	if !ok {
		return cli.ExitUsage
	}
	selPos, add, rem, err := splitUpdateArgs(p.pos)
	if err != nil {
		return a.argFail("%v", err)
	}
	name, tags, err := selectorFrom(selPos)
	if err != nil {
		return a.argFail("%v", err)
	}
	if name == "" && len(tags) == 0 {
		return a.usageFail(updateUsage)
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
		return a.usageFail(updateUsage)
	}
	if len(body) == 1 {
		return a.usageFail(updateUsage)
	}
	c, _, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v", err)
	}
	rows, err := a.listSecrets(c, name, tags)
	if err != nil {
		return a.report(err, func(t string) string { return "ku secret update " + t })
	}
	if len(rows) == 0 {
		return a.fail("No matching secret.")
	}
	if p.flags["name"] != "" && len(rows) != 1 {
		return a.fail("--name works on exactly one secret. Add a tag to pick one")
	}
	if n := len(rows); n > 1 {
		fmt.Fprintln(a.err, previewLines(rows))
		what := fmt.Sprintf("%d secrets will change.", n)
		switch authorize {
		case "on":
			what = fmt.Sprintf("%d secrets will ask for a confirmation.", n)
		case "off":
			what = fmt.Sprintf("%d secrets will stop asking for a confirmation.", n)
		}
		ok, cerr := a.confirm(what+" Continue?", p.has("yes"))
		if cerr != nil {
			return a.fail("%v", cerr)
		}
		if !ok {
			return a.fail("Nothing changed")
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
		a.say("✓ Renamed %s to %s", rows[0].Name, body["rename"])
	case len(res.Updated) == 1:
		n, _ := splitItem(res.Updated[0])
		a.say("✓ Updated %s", n)
	default:
		a.say("✓ Updated %d secrets", len(res.Updated))
	}
	return 0
}

// secretBulk is revoke and archive: preview the list and confirm when several secrets are selected.
func (a *app) secretBulk(args []string, verb string) int {
	line := map[string]string{"revoke": revokeUsage, "archive": archiveUsage}[verb]
	p, ok := a.parse(line, args, []string{"profile"}, "yes")
	if !ok {
		return cli.ExitUsage
	}
	name, tags, err := selectorFrom(p.pos)
	if err != nil {
		return a.argFail("%v", err)
	}
	if name == "" && len(tags) == 0 {
		return a.usageFail(line)
	}
	c, _, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v", err)
	}
	rows, err := a.listSecrets(c, name, tags)
	if err != nil {
		return a.report(err, func(t string) string { return "ku secret " + verb + " " + t })
	}
	if len(rows) == 0 {
		return a.fail("No matching secret.")
	}
	if len(rows) > 1 {
		fmt.Fprintln(a.err, previewLines(rows))
		past := map[string]string{"revoke": "revoked", "archive": "archived"}[verb]
		ok, cerr := a.confirm(fmt.Sprintf("%d secrets will be %s. Continue?", len(rows), past), p.has("yes"))
		if cerr != nil {
			return a.fail("%v", cerr)
		}
		if !ok {
			return a.fail("Nothing changed")
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
		a.say("✓ Revoked %s. It stays blocked until you save a new value.", rows[0].Name)
	case verb == "revoke":
		a.say("✓ Revoked %d secrets. They stay blocked until you save new values.", n)
	case n == 1:
		a.say("✓ Archived %s", rows[0].Name)
	default:
		a.say("✓ Archived %d secrets", n)
	}
	return 0
}

// previewLines lists the selected secrets before a confirmation (same for update, revoke and archive).
func previewLines(rows []secretRow) string {
	items := make([]string, len(rows))
	for i, r := range rows {
		items[i] = strings.TrimSpace(r.Name + " " + strings.Join(r.Tags, " "))
	}
	return itemLines(items, "  ")
}
