package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/victorlunam/kuukura/identity"
)

// positional parses args into exactly n positional arguments plus the flags declared on fs.
func positional(fs *flag.FlagSet, usage string, args []string, n int) ([]string, error) {
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) != n { // the flag package's error would name what was typed
		return nil, usageError("ku-server " + usage)
	}
	return pos, nil
}

func runUserList(args []string) error {
	if err := noArgs("user list", args); err != nil {
		return err
	}
	return withApp(func(ctx context.Context, a *app) error {
		people, err := a.ids.ListPeople(ctx)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tKIND\tROLE\tSTATUS\tFACTORS\tCREATED")
		for _, p := range people {
			role := p.Role
			if role == "" {
				role = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n", p.Name, p.Kind, role, p.Status, p.Factors, p.Created.UTC().Format(time.DateOnly))
		}
		return w.Flush()
	})
}

const inviteUsage = "user invite <email> [--admin]"

// runUserInvite prints a single-use, 15 minute link to the terminal. The link is never logged or audited.
func runUserInvite(args []string) error {
	fs := newFlags("user invite")
	admin := fs.Bool("admin", false, "invite an admin instead of a member")
	pos, err := positional(fs, inviteUsage, args, 1)
	if err != nil {
		return err
	}
	return withApp(func(ctx context.Context, a *app) error {
		inv, err := a.ids.InviteByHost(ctx, pos[0], *admin)
		if err != nil {
			return err
		}
		printLink(a.c, inv)
		return nil
	})
}

func printLink(c config, inv identity.Invite) {
	fmt.Printf("Invite link (single use, valid until %s):\n%s/invite?token=%s\n", inv.ExpiresAt.UTC().Format(time.RFC3339), c.baseURL(), inv.Token)
}

func runUserDisable(args []string) error {
	const usage = "user disable <email|machine-name>"
	pos, err := positional(newFlags("user disable"), usage, args, 1)
	if err != nil {
		return err
	}
	return withApp(func(ctx context.Context, a *app) error {
		if err := a.ids.DisableByHost(ctx, pos[0]); err != nil {
			return err
		}
		fmt.Printf("Disabled %s: their sessions and tokens, and the machines they own, no longer work.\n", pos[0])
		return nil
	})
}

func runUserEnable(args []string) error {
	const usage = "user enable <email|machine-name>"
	pos, err := positional(newFlags("user enable"), usage, args, 1)
	if err != nil {
		return err
	}
	return withApp(func(ctx context.Context, a *app) error {
		status, err := a.ids.EnableByHost(ctx, pos[0])
		if err != nil {
			return err
		}
		fmt.Printf("Enabled %s (%s). Tokens revoked by the disable stay revoked.\n", pos[0], status)
		return nil
	})
}

// runUserResetFactors is for a person who lost their passkey and recovery codes.
func runUserResetFactors(args []string) error {
	pos, err := positional(newFlags("user reset-factors"), "user reset-factors <email>", args, 1)
	if err != nil {
		return err
	}
	return withApp(func(ctx context.Context, a *app) error {
		inv, err := a.ids.ResetFactorsByHost(ctx, pos[0])
		if err != nil {
			return err
		}
		fmt.Printf("Removed the passkeys, authenticator apps and recovery codes of %s and ended their sessions.\n", pos[0])
		printLink(a.c, inv)
		return nil
	})
}
