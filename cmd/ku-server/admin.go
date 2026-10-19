package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/auth"
	"github.com/victorlunam/kuukura/identity"
	"github.com/victorlunam/kuukura/keys"
	"github.com/victorlunam/kuukura/secrets"
	"github.com/victorlunam/kuukura/storage"
)

func openStorage(ctx context.Context, c config) (storage.Provider, error) {
	if err := storage.Migrate(c.Storage, c.dsn()); err != nil {
		return nil, fmt.Errorf("migrations failed")
	}
	return storage.Open(ctx, c.Storage, c.dsn())
}

func keyProvider(ctx context.Context, c config) (keys.KeyProvider, error) {
	if c.KeyProvider == "aws-kms" {
		return keys.NewKMS(ctx, c.KMSKeyARN)
	}
	return keys.ParseMasterKeys(c.MasterKey)
}

func runAdmin(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ku-server admin <invite|rotate-key>")
	}
	switch args[0] {
	case "invite":
		return adminInvite(args[1:])
	case "rotate-key":
		return adminRotate(args[1:])
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
	fmt.Printf("Invite link (single use, valid until %s):\nhttps://%s/invite?token=%s\n", inv.ExpiresAt.Local().Format("15:04"), c.Domain, inv.Token)
	return nil
}

// adminRotate rewraps every DEK and TOTP secret to the active master key version and audits key_rotate.
// Add the new key version to the key file and restart/run this with it before rotating.
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
	tokens := auth.NewTokens(p)
	nSecrets, err := secrets.New(p, kp, log).RewrapAll(ctx)
	if err != nil {
		return fmt.Errorf("rewrap failed: %w", err)
	}
	a, err := auth.NewService(p, log, tokens, nil, kp, auth.Config{RPID: c.Domain, RPOrigin: "https://" + c.Domain, Issuer: "kuukura"})
	if err != nil {
		return err
	}
	nTOTP, err := a.RewrapTOTP(ctx)
	if err != nil {
		return fmt.Errorf("rewrap failed: %w", err)
	}
	if err := log.Record(ctx, audit.Entry{Principal: who, Action: "key_rotate", TargetType: "key",
		Metadata: map[string]any{"key_id": kp.KeyID(), "secret_versions": nSecrets, "totp": nTOTP}}); err != nil {
		return err
	}
	fmt.Printf("Rewrapped %d secret versions and %d TOTP secrets to %s.\n", nSecrets, nTOTP, kp.KeyID())
	return nil
}
