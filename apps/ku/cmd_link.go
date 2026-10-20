package main

import (
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
	a.say("✓ Linked this folder to %s", app)
	return 0
}
