package main

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const factorUsage = "Use: ku account factor list | add <passkey|totp> | default <id> | remove <id>"

type factor struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Added   string `json:"added"`
	Default bool   `json:"default"`
}

func (a *app) cmdAccount(args []string) int {
	if len(args) == 0 || args[0] != "factor" {
		return a.fail("%s", factorUsage)
	}
	p, err := parseArgs(args[1:], []string{"profile"}, "yes")
	if err != nil {
		return a.fail("%v", err)
	}
	if len(p.pos) == 0 {
		return a.fail("%s", factorUsage)
	}
	sub, pos := p.pos[0], p.pos[1:]
	c, _, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v.", err)
	}
	report := func(err error) int { return a.report(err, func(string) string { return "ku account factor " + sub }) }
	switch {
	case sub == "list" && len(pos) == 0:
		fs, err := a.factors(c)
		if err != nil {
			return report(err)
		}
		for _, f := range fs {
			mark := ""
			if f.Default {
				mark = "  default"
			}
			fmt.Fprintf(a.out, "%s  %-8s  added %s%s\n", f.ID[:min(8, len(f.ID))], factorName(f.Kind), f.Added, mark)
		}
	case sub == "add" && len(pos) == 1 && (pos[0] == "passkey" || pos[0] == "totp"):
		return a.addFactor(c, pos[0], report)
	case sub == "default" && len(pos) == 1:
		return a.defaultFactor(c, pos[0], report)
	case sub == "remove" && len(pos) == 1:
		return a.removeFactor(c, pos[0], p.has("yes"), report)
	default:
		return a.fail("%s", factorUsage)
	}
	return 0
}

func factorName(kind string) string {
	if kind == "totp" {
		return "app"
	}
	return kind
}

func (a *app) factors(c *client) ([]factor, error) {
	var r struct {
		Factors []factor `json:"factors"`
	}
	err := c.call("GET", "/account/factors", nil, &r)
	return r.Factors, err
}

// addFactor confirms with a current second step, then registers the new one in the browser and waits for it.
func (a *app) addFactor(c *client, kind string, report func(error) int) int {
	before, err := a.factors(c)
	if err != nil {
		return report(err)
	}
	var r struct {
		URL string `json:"url"`
	}
	if err := a.callStepUp(c, "factor_add", kind, "POST", "/account/factors", map[string]string{"kind": kind, "profile": c.profile}, &r); err != nil {
		return report(err)
	}
	fmt.Fprintf(a.err, "If the browser does not open, copy this link (it works once):\n  %s\n", r.URL)
	a.openLink(c, r.URL)
	if kind == "passkey" {
		fmt.Fprint(a.err, "Add your passkey in the browser...")
	} else {
		fmt.Fprint(a.err, "Add your authenticator app in the browser...")
	}
	err = a.waitFor(5*time.Minute, func() (bool, error) {
		now, err := a.factors(c)
		return len(now) > len(before), err
	})
	fmt.Fprintln(a.err)
	if errors.Is(err, errTimeout) {
		return a.fail("Timed out waiting for the new second step. Run the command again.")
	}
	if err != nil {
		return report(err)
	}
	a.say("✓ Added %s. See them all with: ku account factor list", factorName(kind))
	return 0
}

// pick finds the one factor whose id starts with prefix (the id shown by `list`; a unique start is enough).
func (a *app) pick(fs []factor, prefix string) (factor, bool) {
	var hit []factor
	for _, f := range fs {
		if strings.HasPrefix(f.ID, strings.ToLower(prefix)) {
			hit = append(hit, f)
		}
	}
	switch len(hit) {
	case 1:
		return hit[0], true
	case 0:
		a.fail("No second step starts with %q. See them with: ku account factor list", prefix)
	default:
		a.fail("%q matches more than one. Type a longer start of the id.", prefix)
	}
	return factor{}, false
}

// defaultFactor makes a factor the one the sign-in and confirmation pages offer first.
func (a *app) defaultFactor(c *client, prefix string, report func(error) int) int {
	fs, err := a.factors(c)
	if err != nil {
		return report(err)
	}
	f, ok := a.pick(fs, prefix)
	if !ok {
		return 1
	}
	if err := c.call("PATCH", "/account/factors/"+f.ID, map[string]bool{"default": true}, nil); err != nil {
		return report(err)
	}
	a.say("✓ The %s is now your default", factorName(f.Kind))
	return 0
}

func (a *app) removeFactor(c *client, prefix string, yes bool, report func(error) int) int {
	fs, err := a.factors(c)
	if err != nil {
		return report(err)
	}
	f, ok := a.pick(fs, prefix)
	if !ok {
		return 1
	}
	if len(fs) == 1 {
		return a.fail("This is your only second step. Add another one first: ku account factor add passkey")
	}
	sure, err := a.confirm(fmt.Sprintf("Remove the %s added %s?", factorName(f.Kind), f.Added), yes)
	if err != nil {
		return a.fail("%v", err)
	}
	if !sure {
		return a.fail("Nothing changed.")
	}
	if err := a.callStepUp(c, "factor_remove", f.ID, "DELETE", "/account/factors/"+f.ID, nil, nil); err != nil {
		var p *problem
		if errors.As(err, &p) && p.Code == "not-found" {
			return a.fail("That second step is already gone.")
		}
		return report(err)
	}
	a.say("✓ Removed the %s", factorName(f.Kind))
	return 0
}
