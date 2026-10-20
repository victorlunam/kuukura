package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/auth"
	"github.com/victorlunam/kuukura/internal/cli"
	"github.com/victorlunam/kuukura/internal/keys"
	"github.com/victorlunam/kuukura/internal/masterkey"
	"github.com/victorlunam/kuukura/internal/secrets"
)

const showHint = "run `ku-server key show` once and store the key in your password manager"

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

// writeNew creates the file (and its directory, 0700) and fails if it exists.
func writeNew(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-chosen path
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// addKeyVersion appends a fresh key at the next version to the key file (write a sibling, then rename, keeping
// mode 0600) and returns the new body. errNotWritable means the key is not somewhere this command can change.
func addKeyVersion(path string) ([]byte, error) {
	old, err := os.ReadFile(path) // #nosec G304 -- operator-chosen path
	if err != nil {
		return nil, err
	}
	m, err := keys.ParseMasterKeys(old)
	if err != nil {
		return nil, err
	}
	next, err := keys.GenerateMasterKey(m.Version() + 1)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- operator-chosen path
	if err != nil {
		return nil, notWritable(err)
	}
	_ = f.Close()
	body := append(m.Ring(), next...)
	tmp := path + ".new"
	_ = os.Remove(tmp)
	if err := writeNew(tmp, body); err != nil {
		return nil, notWritable(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, notWritable(err)
	}
	return body, nil
}

var errNotWritable = errors.New("the key file is not writable")

func notWritable(err error) error {
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS) {
		return errNotWritable
	}
	return err
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
			c.MasterKey = body
			added = c.KeyFile
		}
		kp, err := keyProvider(ctx, c)
		if err != nil {
			return err
		}
		authSvc, err := auth.NewService(a.p, a.log, a.tokens, nil, kp, c.authConfig())
		if err != nil {
			return err
		}
		sec := secrets.New(a.p, kp, a.log)
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

// addVersion appends the next version to the key file, or explains the manual path when the key is not in one.
func (a *app) addVersion() ([]byte, error) {
	if a.c.KeyFile != "" {
		body, err := addKeyVersion(a.c.KeyFile)
		if !errors.Is(err, errNotWritable) {
			return body, err
		}
	}
	next := 2
	if m, err := keys.ParseMasterKeys(a.c.MasterKey); err == nil {
		next = m.Version() + 1
	}
	return nil, fmt.Errorf("the master key is not in a writable key file, so it cannot add a version itself: add the line %d:<base64 of 32 random bytes, e.g. from `openssl rand -base64 32`> where the key lives, restart the server, then run `ku-server key rotate --rewrap-only`", next)
}

// backupWarning is the start-up warning while the active key version has never been shown by `key show` (a generated,
// `key init` or rotated key alike); it is empty when there is nothing to say. With aws-kms there is no key to back up.
func backupWarning(ctx context.Context, a *app, kp keys.KeyProvider, generated bool) (string, error) {
	if a.c.KeyProvider != "manual" {
		return "", nil
	}
	_, shown, err := masterkey.RevealedAt(ctx, a.log, kp.KeyID())
	switch {
	case err != nil:
		return "", err
	case generated:
		return "generated a new master key at " + a.c.KeyFile + "; it has no offline copy yet: " + showHint, nil
	case !shown:
		return "the master key " + kp.KeyID() + " has no offline copy yet: " + showHint, nil
	}
	return "", nil
}

// stdoutIsTerminal is a variable so tests can stand in for a terminal.
var stdoutIsTerminal = func() bool { return term.IsTerminal(int(os.Stdout.Fd())) } // #nosec G115 -- fd fits in int

// runKeyShow prints the key ring once per key version, only to a terminal, and records that it did. "Shown once" is a
// usability guard: it keeps the key out of scrollback and logs and tells the operator to store it, but whoever has
// host access can still read the key file.
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

// generateKey creates the key file for VAULT_MASTER_KEY_GENERATE, but only on a database with no encrypted data:
// a key generated over existing data would lock everything in it forever.
func generateKey(ctx context.Context, a *app) error {
	c := &a.c
	sealed := keys.Sealed{}
	authSvc, err := auth.NewService(a.p, a.log, a.tokens, nil, sealed, c.authConfig())
	if err != nil {
		return err
	}
	has, err := masterkey.HasEncryptedData(ctx, secrets.New(a.p, sealed, a.log), authSvc)
	if err != nil {
		return err
	}
	if has {
		return fmt.Errorf("the master key file %s is missing but the database holds encrypted data; restore the key from your backup", c.KeyFile)
	}
	key, err := keys.GenerateMasterKey(1)
	if err != nil {
		return err
	}
	m, err := keys.ParseMasterKeys(key)
	if err != nil {
		return err
	}
	host, err := a.ids.HostPrincipal(ctx)
	if err != nil {
		return err
	}
	if err := writeNew(c.KeyFile, key); err != nil {
		return err
	}
	c.MasterKey, c.KeyMissing = key, false
	return a.log.Record(ctx, audit.Entry{Principal: host, Action: "create", TargetType: "key", Metadata: map[string]any{"key_id": m.KeyID()}})
}
