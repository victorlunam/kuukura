package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/victorlunam/kuukura/apps/ku-server/api"
	"github.com/victorlunam/kuukura/internal/access"
	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/auth"
	"github.com/victorlunam/kuukura/internal/keys"
	"github.com/victorlunam/kuukura/internal/masterkey"
)

// runServe validates the config, refuses to start without the master key, and serves until SIGTERM/SIGINT.
func runServe(args []string) error {
	if err := noArgs("serve", args); err != nil {
		return err
	}
	c, err := loadConfig(true)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	p, err := openStorage(ctx, c)
	if err != nil {
		return err
	}
	defer p.Close()
	if err := p.CheckAuditProtected(ctx, p.DB()); err != nil {
		return err
	}
	a := newApp(c, p)
	generated := a.c.KeyMissing
	if generated {
		if err := generateKey(ctx, a); err != nil {
			return err
		}
	}
	kp, err := keyProvider(ctx, a.c)
	if err != nil {
		return fmt.Errorf("cannot load the master key: %w", err)
	}
	google, err := auth.NewGoogle(ctx, c.OIDCClientID, c.OIDCSecret, c.baseURL()+"/auth/callback")
	if err != nil {
		return fmt.Errorf("cannot reach the login provider: %w", err)
	}
	secretsSvc, authSvc, err := a.services(kp, google)
	if err != nil {
		return err
	}
	if err := masterkey.Check(ctx, secretsSvc, authSvc); err != nil {
		return err
	}
	warn, err := backupWarning(ctx, a, kp, generated)
	if err != nil {
		return err
	}
	if warn != "" {
		log.Warn(warn)
	}
	srv := api.New(api.Deps{
		Secrets: secretsSvc, Admin: access.NewAdmin(p, a.log), Identity: a.ids,
		Auth: authSvc, Tokens: a.tokens, Audit: a.log, Storage: p, BaseURL: c.baseURL(), AllowHTTP: c.DevHTTP, Name: c.Name, Log: log,
	})
	hs := &http.Server{Addr: c.Addr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}

	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("listening", "addr", c.Addr, "storage", c.Storage, "key_provider", c.KeyProvider)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return hs.Shutdown(sctx)
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

// generateKey creates the key file for VAULT_MASTER_KEY_GENERATE, but only on a database with no encrypted data:
// a key generated over existing data would lock everything in it forever.
func generateKey(ctx context.Context, a *app) error {
	c := &a.c
	sec, authSvc, err := a.services(keys.Sealed{}, nil)
	if err != nil {
		return err
	}
	has, err := masterkey.HasEncryptedData(ctx, sec, authSvc)
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
