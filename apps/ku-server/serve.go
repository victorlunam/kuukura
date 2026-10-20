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
	"github.com/victorlunam/kuukura/internal/auth"
	"github.com/victorlunam/kuukura/internal/masterkey"
	"github.com/victorlunam/kuukura/internal/secrets"
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
	authSvc, err := auth.NewService(p, a.log, a.tokens, google, kp, c.authConfig())
	if err != nil {
		return err
	}
	secretsSvc := secrets.New(p, kp, a.log)
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
