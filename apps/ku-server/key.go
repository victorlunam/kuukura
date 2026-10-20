package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/victorlunam/kuukura/internal/cli"
	"github.com/victorlunam/kuukura/internal/keys"
	"github.com/victorlunam/kuukura/internal/masterkey"
)

// runKeyInit writes a new master key file (mode 0600, never over an existing file) to mount as a Docker secret.
// The key is never printed: `key show` is the one way to get a copy.
func runKeyInit(args []string) error {
	fs := newFlags("key init")
	keyFile := fs.String("key-file", "", "where to write the master key file (default VAULT_MASTER_KEY_FILE)")
	if _, err := positional(fs, "key init [--key-file <path>]", args, 0); err != nil {
		return err
	}
	path := *keyFile
	if path == "" {
		path = env("VAULT_MASTER_KEY_FILE")
	}
	if path == "" {
		return cli.UsageError("ku-server key init --key-file <path>")
	}
	key, err := keys.GenerateMasterKey(1)
	if err != nil {
		return err
	}
	if err := writeNew(path, key); err != nil {
		return err
	}
	fmt.Println("This file is your master key. Once the server runs, " + showHint + ".")
	return nil
}

// runKeyRotate adds a key version to the key file and rewraps every DEK and TOTP secret to it, together with the
// key_rotate audit row, in one transaction. When the key does not live in a writable file (an environment variable,
// a Docker secret) it cannot add the version itself: add it there, restart, then run it with --rewrap-only. With
// aws-kms, rotating means rewrapping to the configured ARN.
func runKeyRotate(args []string) error {
	fs := newFlags("key rotate")
	rewrapOnly := fs.Bool("rewrap-only", false, "rewrap to the active key without adding a version")
	if _, err := positional(fs, "key rotate [--rewrap-only]", args, 0); err != nil {
		return err
	}
	return withApp(func(ctx context.Context, a *app) error {
		c := a.c
		host, err := a.ids.HostPrincipal(ctx)
		if err != nil {
			return err
		}
		added := ""
		if c.KeyProvider == "manual" && !*rewrapOnly {
			body, err := a.addVersion()
			if err != nil {
				return err
			}
			a.c.MasterKey = body
			added = c.KeyFile
		}
		kp, err := keyProvider(ctx, a.c)
		if err != nil {
			return err
		}
		sec, authSvc, err := a.services(kp, nil)
		if err != nil {
			return err
		}
		nSecrets, nTOTP, err := masterkey.Rewrap(ctx, a.p, sec, authSvc, host)
		if err != nil {
			if added != "" {
				return fmt.Errorf("rewrap failed: %w; the key file already has the new version, so fix the cause and run `ku-server key rotate --rewrap-only` (not rotate again)", err)
			}
			return fmt.Errorf("rewrap failed: %w", err)
		}
		if added != "" {
			fmt.Printf("Added a new key version to %s.\n", added)
		}
		fmt.Printf("Rewrapped %d secret versions and %d TOTP secrets to %s.\n", nSecrets, nTOTP, kp.KeyID())
		fmt.Println("Restart the server so it loads the new key.")
		if c.KeyProvider == "manual" {
			fmt.Println("Run `ku-server key show` to back up the new key version.")
		}
		return nil
	})
}

// stdoutIsTerminal is a variable so tests can stand in for a terminal.
var stdoutIsTerminal = func() bool { return term.IsTerminal(int(os.Stdout.Fd())) } // #nosec G115 -- fd fits in int

// runKeyShow prints the key ring once per key version, only to a terminal, and records that it did (the rule
// itself lives in masterkey).
func runKeyShow(args []string) error {
	if err := noArgs("key show", args); err != nil {
		return err
	}
	return withApp(func(ctx context.Context, a *app) error {
		if a.c.KeyProvider == "aws-kms" {
			fmt.Println("Not applicable: the key never leaves KMS.")
			return nil
		}
		if !stdoutIsTerminal() {
			return errors.New("run it in an interactive terminal: docker exec -it <container> /ku-server key show")
		}
		kp, err := manualKeys(a.c)
		if err != nil {
			return err
		}
		if at, shown, err := masterkey.RevealedAt(ctx, a.log, kp.KeyID()); err != nil {
			return err
		} else if shown {
			where := "The key is in VAULT_MASTER_KEY: read it from your platform's environment settings"
			if a.c.KeyFile != "" {
				where = fmt.Sprintf("The key file %s is the source of truth; copy it from the volume with host access", a.c.KeyFile)
			}
			return fmt.Errorf("the key (%s) was already shown on %s. %s", kp.KeyID(), at.UTC().Format(time.DateOnly), where)
		}
		host, err := a.ids.HostPrincipal(ctx)
		if err != nil {
			return err
		}
		if err := masterkey.RecordReveal(ctx, a.log, host, kp.KeyID()); err != nil {
			return err
		}
		fmt.Printf("\n%s\nStore this in your password manager now (key %s). It will not be shown again.\n", strings.TrimSpace(string(kp.Ring())), kp.KeyID())
		fmt.Println("Anyone with this key and a copy of the database can read every secret.")
		fmt.Println("To restore: put this text in the key file (VAULT_MASTER_KEY_FILE) or in VAULT_MASTER_KEY.")
		fmt.Println("If you need an encrypted file instead, encrypt the text with your own tool (age, gpg, sops).")
		return nil
	})
}
