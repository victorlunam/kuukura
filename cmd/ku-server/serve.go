package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/victorlunam/kuukura/access"
	"github.com/victorlunam/kuukura/api"
	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/auth"
	"github.com/victorlunam/kuukura/identity"
	"github.com/victorlunam/kuukura/secrets"
)

// runServe validates the config, refuses to start without the master key, and serves until SIGTERM/SIGINT.
func runServe(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: ku-server serve")
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
	kp, err := keyProvider(ctx, c)
	if err != nil {
		return errors.New("cannot load the master key")
	}
	google, err := auth.NewGoogle(ctx, c.OIDCClientID, c.OIDCSecret, "https://"+c.Domain+"/auth/callback")
	if err != nil {
		return errors.New("cannot reach the login provider")
	}
	alog, tokens := audit.New(p), auth.NewTokens(p)
	authSvc, err := auth.NewService(p, alog, tokens, google, kp, auth.Config{RPID: c.Domain, RPOrigin: "https://" + c.Domain, Issuer: "kuukura"})
	if err != nil {
		return err
	}
	srv := api.New(api.Deps{
		Secrets: secrets.New(p, kp, alog), Admin: access.NewAdmin(p, alog), Identity: identity.New(p, alog, tokens),
		Auth: authSvc, Tokens: tokens, Audit: alog, Storage: p, Domain: c.Domain, Log: log,
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
