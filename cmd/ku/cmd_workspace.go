package main

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

func (a *app) cmdWorkspace(args []string) int {
	if len(args) == 0 {
		return a.fail("Use: ku workspace invite|group|grant|ungrant|remove|audit")
	}
	sub := args[0]
	p, err := parseArgs(args[1:], "profile")
	if err != nil {
		return a.fail("%v", err)
	}
	pos := p.pos
	switch sub {
	case "invite", "group", "grant", "ungrant", "remove", "audit":
	default:
		return a.fail("Use: ku workspace invite|group|grant|ungrant|remove|audit")
	}
	if sub == "audit" {
		return a.workspaceAudit(p)
	}
	c, _, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v.", err)
	}
	report := func(err error) int {
		return a.report(err, func(t string) string { return "ku workspace " + sub + " ..." })
	}
	switch sub {
	case "invite":
		if len(pos) != 1 {
			return a.fail("Use: ku workspace invite <email> or ku workspace invite <name> --machine")
		}
		if p.has("machine") {
			var r struct {
				Token string `json:"token"`
			}
			if err := c.call("POST", "/workspace/invites", map[string]any{"name": pos[0], "machine": true}, &r); err != nil {
				return report(err)
			}
			fmt.Fprintf(a.out, "✓ Created %s. This token is shown once. Store it in CI as KU_TOKEN:\n%s\n", pos[0], r.Token)
			return 0
		}
		var r struct {
			Link string `json:"link"`
		}
		if err := c.call("POST", "/workspace/invites", map[string]any{"email": pos[0], "profile": c.profile}, &r); err != nil {
			return report(err)
		}
		fmt.Fprintf(a.out, "✓ Invited %s. Send them this link (valid 24 hours, works once):\n%s\n", pos[0], r.Link)
	case "group":
		if len(pos) < 2 {
			return a.fail("Use: ku workspace group <group> +<identity> -<identity>")
		}
		var add, remove []string
		for _, t := range pos[1:] {
			switch {
			case strings.HasPrefix(t, "+") && len(t) > 1:
				add = append(add, t[1:])
			case strings.HasPrefix(t, "-") && len(t) > 1:
				remove = append(remove, t[1:])
			default:
				return a.fail("Use +<identity> to add and -<identity> to remove.")
			}
		}
		if err := c.call("PATCH", "/workspace/groups/"+url.PathEscape(pos[0]), map[string]any{"add": nonNilTags(add), "remove": nonNilTags(remove)}, nil); err != nil {
			return report(err)
		}
		fmt.Fprintf(a.out, "✓ Updated group %s\n", pos[0])
	case "grant":
		if len(pos) < 3 {
			return a.fail("Use: ku workspace grant <identity|group> <read|write> <tags>")
		}
		if err := c.call("POST", "/workspace/grants", map[string]any{"subject": pos[0], "permission": pos[1], "tags": pos[2:]}, nil); err != nil {
			return report(err)
		}
		fmt.Fprintf(a.out, "✓ %s can now %s secrets tagged %s\n", pos[0], pos[1], strings.Join(pos[2:], " "))
	case "ungrant":
		if len(pos) < 2 {
			return a.fail("Use: ku workspace ungrant <identity|group> <tags>")
		}
		if err := c.call("DELETE", "/workspace/grants", map[string]any{"subject": pos[0], "tags": pos[1:]}, nil); err != nil {
			return report(err)
		}
		fmt.Fprintf(a.out, "✓ Removed access for %s to %s\n", pos[0], strings.Join(pos[1:], " "))
	case "remove":
		if len(pos) != 1 {
			return a.fail("Use: ku workspace remove <identity>")
		}
		if err := c.call("PATCH", "/workspace/identities/"+url.PathEscape(pos[0]), map[string]string{"status": "disabled"}, nil); err != nil {
			var pr *problem
			if errors.As(err, &pr) && pr.Code == "last-admin" {
				return a.fail("That is the last admin. Make someone else an admin first.")
			}
			return report(err)
		}
		fmt.Fprintf(a.out, "✓ Removed %s. Their sessions have ended.\n", pos[0])
	}
	return 0
}

func (a *app) workspaceAudit(p parsed) int {
	name, tags, err := selectorFrom(p.pos)
	if err != nil {
		return a.fail("%v.", err)
	}
	c, _, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v.", err)
	}
	q := url.Values{}
	if name != "" {
		q.Set("name", name)
	}
	if len(tags) > 0 {
		q.Set("tags", strings.Join(tags, ","))
	}
	var r struct {
		Rows []struct {
			At        string `json:"at"`
			Principal string `json:"principal"`
			Action    string `json:"action"`
			Secret    string `json:"secret"`
			Version   *int   `json:"version"`
			Result    string `json:"result"`
		} `json:"rows"`
	}
	if err := c.call("GET", "/workspace/audit?"+q.Encode(), nil, &r); err != nil {
		return a.report(err, func(t string) string { return "ku workspace audit " + t })
	}
	if len(r.Rows) == 0 {
		fmt.Fprintln(a.out, "Nothing recorded yet.")
		return 0
	}
	fmt.Fprintf(a.out, "%-21s%-30s%-18s%-20s%s\n", "WHEN (UTC)", "WHO", "ACTION", "SECRET", "RESULT")
	for _, x := range r.Rows {
		sec := x.Secret
		if x.Version != nil {
			sec = fmt.Sprintf("%s v%d", sec, *x.Version)
		}
		fmt.Fprintf(a.out, "%-21s%-30s%-18s%-20s%s\n", strings.Replace(strings.TrimSuffix(x.At, "Z"), "T", " ", 1), x.Principal, x.Action, sec, x.Result)
	}
	return 0
}
