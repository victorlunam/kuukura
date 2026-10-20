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
	const linkUsage = "ku link [<app>] [--profile <name>]"
	p, ok := a.parse(linkUsage, args, []string{"profile"})
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
	return a.createApp(app, p.flags["profile"])
}

// createApp runs after the folder is linked: the server creates the app when it is new and gives the caller write
// access, and says app-exists when not (so linking again is harmless). The link is already saved, so a failure
// here never undoes it. Machines (KU_URL + KU_TOKEN) never create apps.
func (a *app) createApp(name, flagProfile string) int {
	linked := func() { a.say("✓ Linked this folder to %s", name) }
	c, pr, err := a.withProfile(flagProfile, true)
	if err != nil {
		linked()
		if pr.ephemeral {
			return 0
		}
		return a.fail("%v", err)
	}
	if pr.ephemeral {
		linked()
		return 0
	}
	err = c.call("POST", "/apps", map[string]string{"name": name}, nil)
	var pb *problem
	switch {
	case err == nil:
		a.say("✓ Created app %s and linked this folder; you can write its secrets", name)
	case errors.As(err, &pb) && pb.Code == "app-exists":
		linked()
		if rows, lerr := a.listSecrets(c, "", []string{"app:" + name}); lerr != nil || len(rows) == 0 {
			a.say("  %s already exists. If you can't read or write its secrets, ask an admin: ku workspace grant <you> write app:%s", name, name)
		}
	default:
		linked()
		return a.fail("The app could not be created on the server: %s", plain(err))
	}
	return 0
}
