package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/auth"
	"github.com/victorlunam/kuukura/identity"
	"github.com/victorlunam/kuukura/keys"
	"github.com/victorlunam/kuukura/secrets"
	"github.com/victorlunam/kuukura/storage"
)

func openStorage(ctx context.Context, c config) (storage.Provider, error) {
	if err := storage.Migrate(c.Storage, c.migrateDSN()); err != nil {
		return nil, fmt.Errorf("migrations failed: %s", c.scrub(err))
	}
	p, err := storage.Open(ctx, c.Storage, c.dsn())
	if err != nil {
		return nil, fmt.Errorf("cannot connect to the database: %s", c.scrub(err))
	}
	return p, nil
}

func keyProvider(ctx context.Context, c config) (keys.KeyProvider, error) {
	if c.KeyProvider == "aws-kms" {
		return keys.NewKMS(ctx, c.KMSKeyARN)
	}
	return keys.ParseMasterKeys(c.MasterKey)
}

func runAdmin(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ku-server admin <invite|rotate-key|verify-audit>")
	}
	switch args[0] {
	case "invite":
		return adminInvite(args[1:])
	case "rotate-key":
		return adminRotate(args[1:])
	case "verify-audit":
		return adminVerifyAudit(args[1:])
	}
	return fmt.Errorf("unknown admin command %q", args[0])
}

// adminInvite prints a single-use, 15 minute first-admin / break-glass link to the terminal.
// The link is never logged or audited.
func adminInvite(args []string) error {
	fs := flag.NewFlagSet("admin invite", flag.ContinueOnError)
	email := fs.String("email", "", "email of the admin to invite")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return errors.New("usage: ku-server admin invite --email <email>")
	}
	ctx := context.Background()
	c, err := loadConfig(false)
	if err != nil {
		return err
	}
	p, err := openStorage(ctx, c)
	if err != nil {
		return err
	}
	defer p.Close()
	inv, err := identity.New(p, audit.New(p), auth.NewTokens(p)).BootstrapAdmin(ctx, *email)
	if err != nil {
		return err
	}
	fmt.Printf("Invite link (single use, valid until %s):\n%s/invite?token=%s\n", inv.ExpiresAt.UTC().Format(time.RFC3339), c.baseURL(), inv.Token)
	return nil
}

// adminVerifyAudit recomputes the whole audit hash chain and prints the number of rows and the head hash. Store
// the head somewhere the database's operator cannot edit: the chain alone shows edits and deletions in the
// middle, only a remembered head shows that the newest rows were cut off. It fails (exit 1) if the chain is broken.
func adminVerifyAudit(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: ku-server admin verify-audit")
	}
	ctx := context.Background()
	c, err := loadConfig(false)
	if err != nil {
		return err
	}
	p, err := openStorage(ctx, c)
	if err != nil {
		return err
	}
	defer p.Close()
	head, err := audit.New(p).VerifyHead(ctx)
	if err != nil {
		return fmt.Errorf("the audit log does not verify: %w", err)
	}
	fmt.Printf("OK: audit log verified, %d rows, head %x\n", head.Rows, head.Hash)
	return nil
}

// adminRotate rewraps every DEK and TOTP secret to the active master key and audits key_rotate. The active key is
// the highest version in the key file (or VAULT_KMS_KEY_ARN): add the new one and run this with it.
func adminRotate(args []string) error {
	fs := flag.NewFlagSet("admin rotate-key", flag.ContinueOnError)
	by := fs.String("admin", "", "email of the active admin recorded in the audit log")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *by == "" {
		return errors.New("usage: ku-server admin rotate-key --admin <email>")
	}
	ctx := context.Background()
	c, err := loadConfig(false)
	if err != nil {
		return err
	}
	p, err := openStorage(ctx, c)
	if err != nil {
		return err
	}
	defer p.Close()
	kp, err := keyProvider(ctx, c)
	if err != nil {
		return err
	}
	var who uuid.UUID
	if err := p.DB().QueryRowContext(ctx, p.Rebind(`SELECT id FROM principals WHERE name = ? AND role = 'admin' AND status = 'active'`), *by).Scan(&who); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("no active admin with that email")
		}
		return err
	}
	log := audit.New(p)
	a, err := auth.NewService(p, log, auth.NewTokens(p), nil, kp, auth.Config{RPID: c.Domain, RPOrigin: c.baseURL(), Issuer: "kuukura"})
	if err != nil {
		return err
	}
	// TOTP first, in its own transaction (it lives in auth), then the secrets together with the audit row: the
	// row exists only if both are done, and both steps skip what is already on the active key, so a failed run
	// can simply be repeated.
	nTOTP, err := a.RewrapTOTP(ctx)
	if err != nil {
		return fmt.Errorf("rewrap failed: %w", err)
	}
	nSecrets, err := secrets.New(p, kp, log).RewrapAll(ctx, who, nTOTP)
	if err != nil {
		return fmt.Errorf("rewrap failed: %w", err)
	}
	fmt.Printf("Rewrapped %d secret versions and %d TOTP secrets to %s.\n", nSecrets, nTOTP, kp.KeyID())
	return nil
}
