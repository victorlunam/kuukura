package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/victorlunam/kuukura/internal/cli"
)

// cmdLink links the current folder to an app (local alias only; nothing in the repo or on the server).
func (a *app) cmdLink(args []string) int {
	const linkUsage = "ku link [<app>] [--create] [--profile <name>]"
	p, ok := a.parse(linkUsage, args, []string{"profile"}, "create")
	if !ok {
		return cli.ExitUsage
	}
	if len(p.pos) > 1 {
		return a.usageFail(linkUsage)
	}
	if len(p.pos) == 0 {
		l, ok, err := a.currentLink(a.cwd)
		if err != nil {
			return a.fail("%v", err)
		}
		if !ok {
			return a.failNext("ku link <app>", "This folder is not linked to an app")
		}
		fmt.Fprintf(a.out, "This folder is linked to %s\n", l.App)
		return 0
	}
	app := strings.ToLower(p.pos[0])
	if !tagPartRE.MatchString(app) {
		return a.argFail("App names use a-z, 0-9, dot, dash and underscore")
	}
	l := link{App: app, Profile: p.flags["profile"]}
	if l.Profile != "" {
		cfg, err := a.loadConfig()
		if err != nil {
			return a.fail("%v", err)
		}
		if _, ok := cfg.Profiles[l.Profile]; !ok {
			return a.failNext("ku profile list", "Unknown profile %s", l.Profile)
		}
	}
	links, err := a.loadLinks()
	if err != nil {
		return a.fail("%v", err)
	}
	links[filepath.Clean(a.cwd)] = l
	if err := a.saveLinks(links); err != nil {
		return a.fail("%v", err)
	}
	a.say("✓ Linked this folder to %s", app)
	return a.createApp(app, p)
}

// createApp offers to create the app the folder was just linked to. It asks the server only when the person said
// so (--create or a yes on a terminal): the server gives write access when the app is new, and says so when not.
// The link is already saved, so a refusal here never undoes it. Machines never create apps.
func (a *app) createApp(name string, p parsed) int {
	explicit := p.has("create")
	if !explicit && !a.isTTY {
		return 0
	}
	c, pr, err := a.withProfile(p.flags["profile"], true)
	if err != nil { // not signed in: linking works offline, creating does not
		if explicit {
			return a.fail("%v", err)
		}
		return 0
	}
	if pr.ephemeral {
		if explicit {
			return a.fail("A machine token cannot create apps")
		}
		return 0
	}
	if !explicit {
		if ok, _ := a.confirm("Create app "+name+" and give you write access if it is new?", false); !ok {
			return 0
		}
	}
	err = c.call("POST", "/apps", map[string]string{"name": name}, nil)
	var pb *problem
	switch {
	case err == nil:
		a.say("✓ Created app %s; you can write its secrets", name)
	case errors.As(err, &pb) && pb.Code == "app-exists":
		a.say("  %s already exists. To get access, ask an admin: ku workspace grant <you> write app:%s", name, name)
	default:
		return a.fail("%s", plain(err))
	}
	return 0
}
