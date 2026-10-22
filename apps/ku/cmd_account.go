package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/victorlunam/kuukura/internal/cli"
)

const factorUsage = "ku account factor list | add <passkey|totp> | default <id> | remove <id>"

type factor struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Added   string `json:"added"`
	Default bool   `json:"default"`
}

func (a *app) cmdAccount(args []string) int {
	if len(args) == 0 || args[0] != "factor" {
		return a.usageFail(factorUsage)
	}
	p, ok := a.parse(factorUsage, args[1:], []string{"profile"}, "yes")
	if !ok {
		return cli.ExitUsage
	}
	if len(p.pos) == 0 {
		return a.usageFail(factorUsage)
	}
	sub, pos := p.pos[0], p.pos[1:]
	if !validFactorCall(sub, pos) {
		return a.usageFail(factorUsage)
	}
	c, _, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v", err)
	}
	report := func(err error) int { return a.report(err, nil) }
	switch sub {
	case "list":
		fs, err := a.factors(c)
		if err != nil {
			return report(err)
		}
		for _, f := range fs {
			mark := ""
			if f.Default {
				mark = "  default"
			}
			fmt.Fprintf(a.out, "%s  %-17s  added %s%s\n", f.ID[:min(8, len(f.ID))], factorName(f.Kind), f.Added, mark)
		}
	case "add":
		return a.addFactor(c, pos[0], report)
	case "default":
		return a.defaultFactor(c, pos[0], report)
	case "remove":
		return a.removeFactor(c, pos[0], p.has("yes"), report)
	}
	return 0
}

// validFactorCall checks the shape of `ku account factor <sub> <pos...>` before anything talks to the server.
func validFactorCall(sub string, pos []string) bool {
	switch sub {
	case "list":
		return len(pos) == 0
	case "add":
		return len(pos) == 1 && (pos[0] == "passkey" || pos[0] == "totp")
	case "default", "remove":
		return len(pos) == 1
	}
	return false
}

// factorName is what a person calls a kind of factor.
func factorName(kind string) string {
	if kind == "totp" {
		return "authenticator app"
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

// addFactor confirms with a current passkey or authenticator app, then registers the new one in the browser and waits for it.
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
		return a.failNext("ku account factor add "+kind, "Timed out waiting for the browser")
	}
	if err != nil {
		return report(err)
	}
	a.say("✓ Added the %s. See them all with: ku account factor list", factorName(kind))
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
		a.failNext("ku account factor list", "No passkey or authenticator app starts with %q", prefix)
	default:
		a.fail("%q matches more than one. Type a longer start of the id", prefix)
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
		return a.failNext("ku account factor add passkey", "This is your only passkey or authenticator app. Add another one first")
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
			return a.fail("That passkey or authenticator app is already gone")
		}
		return report(err)
	}
	a.say("✓ Removed the %s", factorName(f.Kind))
	return 0
}
