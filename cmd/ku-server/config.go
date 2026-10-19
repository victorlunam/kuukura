package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// config is read from the environment and validated at startup (fail fast).
// Values never appear in error messages.
type config struct {
	Domain       string // VAULT_DOMAIN: instance domain, also the WebAuthn RP ID
	Addr         string // VAULT_ADDR, default :8080
	Storage      string // VAULT_STORAGE: sqlite | postgres
	SQLitePath   string // VAULT_SQLITE_PATH
	DatabaseURL  string // VAULT_DATABASE_URL
	KeyProvider  string // VAULT_KEY_PROVIDER: manual (default) | aws-kms
	MasterKey    []byte // from VAULT_MASTER_KEY_FILE (preferred) or VAULT_MASTER_KEY
	KMSKeyARN    string // VAULT_KMS_KEY_ARN
	OIDCClientID string // VAULT_OIDC_CLIENT_ID
	OIDCSecret   string // VAULT_OIDC_CLIENT_SECRET (or VAULT_OIDC_CLIENT_SECRET_FILE)
}

func env(k string) string { return strings.TrimSpace(os.Getenv(k)) }

func fileOrEnv(fileKey, envKey string) (string, error) {
	if f := env(fileKey); f != "" {
		b, err := os.ReadFile(f) // #nosec G304 -- operator-provided secret file path
		if err != nil {
			return "", fmt.Errorf("cannot read %s", fileKey)
		}
		return string(b), nil
	}
	return os.Getenv(envKey), nil
}

// loadConfig validates everything the commands share. needServe adds the
// settings only the HTTP server needs.
func loadConfig(needServe bool) (config, error) {
	c := config{
		Domain: env("VAULT_DOMAIN"), Addr: env("VAULT_ADDR"), Storage: env("VAULT_STORAGE"),
		SQLitePath: env("VAULT_SQLITE_PATH"), DatabaseURL: env("VAULT_DATABASE_URL"),
		KeyProvider: env("VAULT_KEY_PROVIDER"), KMSKeyARN: env("VAULT_KMS_KEY_ARN"),
		OIDCClientID: env("VAULT_OIDC_CLIENT_ID"),
	}
	var errs []error
	need := func(ok bool, msg string) {
		if !ok {
			errs = append(errs, errors.New(msg))
		}
	}
	need(c.Domain != "" && !strings.ContainsAny(c.Domain, "/: "), "VAULT_DOMAIN must be a bare domain name, e.g. vault.example.com")
	if c.Addr == "" {
		c.Addr = ":8080"
	}
	switch c.Storage {
	case "sqlite":
		need(c.SQLitePath != "", "VAULT_SQLITE_PATH is required with VAULT_STORAGE=sqlite")
	case "postgres":
		need(c.DatabaseURL != "", "VAULT_DATABASE_URL is required with VAULT_STORAGE=postgres")
	default:
		need(false, "VAULT_STORAGE must be sqlite or postgres")
	}
	if c.KeyProvider == "" {
		c.KeyProvider = "manual"
	}
	switch c.KeyProvider {
	case "manual":
		mk, err := fileOrEnv("VAULT_MASTER_KEY_FILE", "VAULT_MASTER_KEY")
		need(err == nil, "cannot read VAULT_MASTER_KEY_FILE")
		need(strings.TrimSpace(mk) != "", "the master key is required: set VAULT_MASTER_KEY_FILE (Docker secret) or VAULT_MASTER_KEY")
		c.MasterKey = []byte(mk)
	case "aws-kms":
		need(c.KMSKeyARN != "", "VAULT_KMS_KEY_ARN is required with VAULT_KEY_PROVIDER=aws-kms")
	default:
		need(false, "VAULT_KEY_PROVIDER must be manual or aws-kms")
	}
	if needServe {
		sec, err := fileOrEnv("VAULT_OIDC_CLIENT_SECRET_FILE", "VAULT_OIDC_CLIENT_SECRET")
		need(err == nil, "cannot read VAULT_OIDC_CLIENT_SECRET_FILE")
		c.OIDCSecret = strings.TrimSpace(sec)
		need(c.OIDCClientID != "" && c.OIDCSecret != "", "VAULT_OIDC_CLIENT_ID and VAULT_OIDC_CLIENT_SECRET are required")
	}
	return c, errors.Join(errs...)
}

func (c config) dsn() string {
	if c.Storage == "sqlite" {
		return c.SQLitePath
	}
	return c.DatabaseURL
}
