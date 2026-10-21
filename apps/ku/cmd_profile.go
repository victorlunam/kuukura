package main

import (
	"fmt"
	"strings"

	"github.com/victorlunam/kuukura/internal/cli"
)

const (
	profileVerbs = "ku profile add|use|list|remove"
	profileAdd   = "ku profile add <name> --url <url>"
)

func (a *app) cmdProfile(args []string) int {
	if len(args) == 0 {
		return a.usageFail(profileVerbs)
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return a.fail("%v", err)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		p, ok := a.parse(profileAdd, rest, []string{"url"})
		if !ok {
			return cli.ExitUsage
		}
		if len(p.pos) != 1 || p.flags["url"] == "" {
			return a.usageFail(profileAdd)
		}
		name := p.pos[0]
		// The server's pages show `ku profile add <alias> --url ...`: the placeholder must be replaced, not kept.
		if strings.Trim(name, "<>") == "alias" {
			return a.argFail("Replace <alias> with a name you choose for this server, for example: ku profile add work --url %s", p.flags["url"])
		}
		if !profileRE.MatchString(name) {
			return a.argFail("Profile names use a-z, 0-9, dot, dash and underscore")
		}
		u, err := validateURL(p.flags["url"])
		if err != nil {
			return a.argFail("%v", err)
		}
		if _, exists := cfg.Profiles[name]; exists {
			return a.fail("Profile %s already exists.", name)
		}
		cfg.Profiles[name] = profileCfg{URL: u}
		if cfg.Active == "" {
			cfg.Active = name
		}
		if err := a.saveConfig(cfg); err != nil {
			return a.fail("%v", err)
		}
		a.say("✓ Added profile %s", name)
	case "use":
		if len(rest) != 1 {
			return a.usageFail("ku profile use <name>")
		}
		if _, ok := cfg.Profiles[rest[0]]; !ok {
			return a.failNext("ku profile list", "Unknown profile %s", rest[0])
		}
		cfg.Active = rest[0]
		if err := a.saveConfig(cfg); err != nil {
			return a.fail("%v", err)
		}
		a.say("✓ Using profile %s", rest[0])
	case "list":
		for _, n := range sortedKeys(cfg.Profiles) {
			mark := " "
			if n == cfg.Active {
				mark = "*"
			}
			fmt.Fprintf(a.out, "%s %s  %s\n", mark, n, cfg.Profiles[n].URL)
		}
	case "remove":
		if len(rest) != 1 {
			return a.usageFail("ku profile remove <name>")
		}
		name := rest[0]
		if _, ok := cfg.Profiles[name]; !ok {
			return a.failNext("ku profile list", "Unknown profile %s", name)
		}
		if err := a.store.Delete(name); err != nil {
			return a.fail("Could not remove the saved session: %v", err)
		}
		delete(cfg.Profiles, name)
		if cfg.Active == name {
			cfg.Active = ""
		}
		if err := a.saveConfig(cfg); err != nil {
			return a.fail("%v", err)
		}
		a.say("✓ Removed profile %s", name)
	default:
		return a.usageFail(profileVerbs)
	}
	return 0
}
