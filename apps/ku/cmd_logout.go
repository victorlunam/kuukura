package main

import (
	"errors"

	"github.com/victorlunam/kuukura/internal/cli"
)

// cmdLogout ends the session on the server and forgets it on this machine. The local copy is deleted even when
// the server cannot be reached: the session then simply runs out (8 h at most, 1 h idle).
func (a *app) cmdLogout(args []string) int {
	const logoutUsage = "ku logout [--profile <name>]"
	p, ok := a.parse(logoutUsage, args, []string{"profile"})
	if !ok {
		return cli.ExitUsage
	}
	if len(p.pos) != 0 {
		return a.usageFail(logoutUsage)
	}
	if a.getenv("KU_URL") != "" || a.getenv("KU_TOKEN") != "" {
		return a.fail("KU_URL or KU_TOKEN is set: a machine token is not a session. An admin ends it with ku workspace disable")
	}
	pr, err := a.resolve(p.flags["profile"])
	if err != nil {
		return a.fail("%v", err)
	}
	a.say("profile: %s", pr.name)
	tok, err := a.store.Get(pr.name)
	if errors.Is(err, errNoToken) || err == nil && tok == "" {
		a.say("✓ Not signed in to %s", pr.name)
		return 0
	}
	if err != nil {
		return a.fail("Cannot read the saved session: %v", err)
	}
	c := &client{a: a, base: pr.url, token: tok, profile: pr.name}
	callErr := c.call("POST", "/auth/logout", nil, nil)
	var pb *problem
	expired := errors.As(callErr, &pb) && pb.Code == "unauthorized" // already over on the server
	if err := a.store.Delete(pr.name); err != nil {
		return a.fail("Could not delete the saved session: %v", err)
	}
	if callErr != nil && !expired {
		a.say("✓ Signed out of %s on this machine", pr.name)
		return a.fail("The server could not be reached to end the session; it expires on its own within 8 hours")
	}
	a.say("✓ Signed out of %s", pr.name)
	return 0
}
