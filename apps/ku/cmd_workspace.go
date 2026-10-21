package main

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/victorlunam/kuukura/internal/cli"
)

// workspaceUsage is the usage line of each `ku workspace` verb.
var workspaceUsage = map[string]string{
	"invite":  "ku workspace invite <email> | <name> --machine",
	"group":   "ku workspace group <group> +<identity> -<identity>",
	"grant":   "ku workspace grant <identity|group> <read|write> <tags>",
	"ungrant": "ku workspace ungrant <identity|group> <tags>",
	"disable": "ku workspace disable <identity>",
	"enable":  "ku workspace enable <identity>",
	"audit":   "ku workspace audit [name] [tags]",
}

// workspaceArity reports whether n positional arguments fit the verb.
func workspaceArity(sub string, n int) bool {
	switch sub {
	case "invite", "disable", "enable":
		return n == 1
	case "group", "ungrant":
		return n >= 2
	case "grant":
		return n >= 3
	}
	return true // audit takes an optional selector
}

const workspaceVerbs = "ku workspace invite|group|grant|ungrant|disable|enable|audit"

func (a *app) cmdWorkspace(args []string) int {
	if len(args) == 0 {
		return a.usageFail(workspaceVerbs)
	}
	sub := args[0]
	line, known := workspaceUsage[sub]
	if !known {
		return a.usageFail(workspaceVerbs)
	}
	p, ok := a.parse(line, args[1:], []string{"profile"}, "machine")
	if !ok {
		return cli.ExitUsage
	}
	pos := p.pos
	if p.has("machine") && sub != "invite" || !workspaceArity(sub, len(pos)) {
		return a.usageFail(line)
	}
	if sub == "audit" {
		return a.workspaceAudit(p)
	}
	c, _, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v", err)
	}
	report := func(err error) int {
		return a.report(err, func(t string) string { return "ku workspace " + sub + " ..." })
	}
	switch sub {
	case "invite":
		if p.has("machine") {
			var r struct {
				Token string `json:"token"`
			}
			if err := c.call("POST", "/workspace/invites", map[string]any{"name": pos[0], "machine": true}, &r); err != nil {
				return report(err)
			}
			a.say("✓ Created %s. This token is shown once. Store it in CI as KU_TOKEN:", pos[0])
			fmt.Fprintln(a.out, r.Token)
			return 0
		}
		var r struct {
			Link string `json:"link"`
		}
		if err := c.call("POST", "/workspace/invites", map[string]any{"email": pos[0], "profile": c.profile}, &r); err != nil {
			return report(err)
		}
		a.say("✓ Invited %s. Send them this link (valid 24 hours, works once):", pos[0])
		fmt.Fprintln(a.out, r.Link)
	case "group":
		var add, remove []string
		for _, t := range pos[1:] {
			switch {
			case strings.HasPrefix(t, "+") && len(t) > 1:
				add = append(add, t[1:])
			case strings.HasPrefix(t, "-") && len(t) > 1:
				remove = append(remove, t[1:])
			default:
				return a.usageFail(line)
			}
		}
		if err := c.call("PATCH", "/workspace/groups/"+url.PathEscape(pos[0]), map[string]any{"add": nonNilTags(add), "remove": nonNilTags(remove)}, nil); err != nil {
			return report(err)
		}
		a.say("✓ Updated group %s", pos[0])
	case "grant":
		if err := checkTags(pos, 2); err != nil {
			return a.argFail("%v", err)
		}
		if err := c.call("POST", "/workspace/grants", map[string]any{"subject": pos[0], "permission": pos[1], "tags": pos[2:]}, nil); err != nil {
			return report(err)
		}
		a.say("✓ %s can now %s secrets tagged %s", pos[0], pos[1], strings.Join(pos[2:], " "))
	case "ungrant":
		if err := checkTags(pos, 1); err != nil {
			return a.argFail("%v", err)
		}
		if err := c.call("DELETE", "/workspace/grants", map[string]any{"subject": pos[0], "tags": pos[1:]}, nil); err != nil {
			return report(err)
		}
		a.say("✓ Removed access for %s to %s", pos[0], strings.Join(pos[1:], " "))
	case "disable":
		if err := c.call("PATCH", "/workspace/identities/"+url.PathEscape(pos[0]), map[string]string{"status": "disabled"}, nil); err != nil {
			return report(err)
		}
		a.say("✓ Disabled %s. Their sessions have ended.", pos[0])
	case "enable":
		var r struct {
			Status string `json:"status"`
		}
		if err := c.call("PATCH", "/workspace/identities/"+url.PathEscape(pos[0]), map[string]string{"status": "active"}, &r); err != nil {
			return report(err)
		}
		if r.Status == "invited" {
			a.say("✓ Enabled %s. They never finished signing up: on the server, `ku-server user invite %s` gives them a new link.", pos[0], pos[0])
			return 0
		}
		a.say("✓ Enabled %s. They can sign in again.", pos[0])
	}
	return 0
}

// checkTags rejects any argument from index first on that is not a tag, without echoing it.
func checkTags(pos []string, first int) error {
	for i := first; i < len(pos); i++ {
		if !tagRE.MatchString(strings.ToLower(pos[i])) {
			return notATag(i + 1)
		}
	}
	return nil
}

func (a *app) workspaceAudit(p parsed) int {
	name, tags, err := selectorFrom(p.pos)
	if err != nil {
		return a.argFail("%v", err)
	}
	c, _, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v", err)
	}
	q := url.Values{}
	if name != "" {
		q.Set("name", name)
	}
	pos, not := splitNot(tags)
	if len(pos) > 0 {
		q.Set("tags", strings.Join(pos, ","))
	}
	if len(not) > 0 {
		q.Set("not", strings.Join(not, ","))
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
		a.say("Nothing recorded yet.")
		return 0
	}
	// Column widths follow the content, so a long email never runs into the next column.
	table := [][]string{{"WHEN (UTC)", "WHO", "ACTION", "SECRET", "RESULT"}}
	for _, x := range r.Rows {
		sec := x.Secret
		if x.Version != nil {
			sec = fmt.Sprintf("%s v%d", sec, *x.Version)
		}
		table = append(table, []string{strings.Replace(strings.TrimSuffix(x.At, "Z"), "T", " ", 1), x.Principal, x.Action, sec, x.Result})
	}
	widths := make([]int, 5)
	for _, row := range table {
		for i, cell := range row {
			widths[i] = max(widths[i], len([]rune(cell)))
		}
	}
	for _, row := range table {
		var b strings.Builder
		for i, cell := range row {
			if i == len(row)-1 {
				b.WriteString(cell)
				break
			}
			b.WriteString(cell)
			b.WriteString(strings.Repeat(" ", widths[i]-len([]rune(cell))+2))
		}
		fmt.Fprintln(a.out, b.String())
	}
	return 0
}
