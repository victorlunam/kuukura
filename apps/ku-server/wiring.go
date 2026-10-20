package main

import (
	"context"
	"fmt"

	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/auth"
	"github.com/victorlunam/kuukura/internal/identity"
	"github.com/victorlunam/kuukura/internal/keys"
	"github.com/victorlunam/kuukura/internal/secrets"
	"github.com/victorlunam/kuukura/internal/storage"
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
	return manualKeys(c)
}

func manualKeys(c config) (*keys.Manual, error) {
	if len(c.MasterKey) == 0 {
		return nil, fmt.Errorf("the master key file %s does not exist yet: start the server once to generate it", c.KeyFile)
	}
	return keys.ParseMasterKeys(c.MasterKey)
}

// app is what every host command works with: the configuration, the database and the services the HTTP API uses.
type app struct {
	c      config
	p      storage.Provider
	log    *audit.Log
	tokens *auth.Tokens
	ids    *identity.Service
}

func newApp(c config, p storage.Provider) *app {
	log, tokens := audit.New(p), auth.NewTokens(p)
	return &app{c, p, log, tokens, identity.New(p, log, tokens)}
}

// withApp loads the configuration, opens the (migrated) database and runs fn.
func withApp(fn func(ctx context.Context, a *app) error) error {
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
	return fn(ctx, newApp(c, p))
}

// services builds the two services that hold data encrypted under kp. prov is the login provider, nil for the
// commands that never sign anyone in.
func (a *app) services(kp keys.KeyProvider, prov auth.AuthProvider) (*secrets.Service, *auth.Service, error) {
	authSvc, err := auth.NewService(a.p, a.log, a.tokens, prov, kp, a.c.authConfig())
	if err != nil {
		return nil, nil, err
	}
	return secrets.New(a.p, kp, a.log), authSvc, nil
}
