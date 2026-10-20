package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/victorlunam/kuukura/internal/auth"
)

// defaultAddr is where the server listens without VAULT_ADDR; the container healthcheck probes the same port.
const defaultAddr = ":8080"

// config is read from the environment and validated at startup (fail fast).
// Values never appear in error messages.
type config struct {
	Domain       string // VAULT_DOMAIN: instance domain, also the WebAuthn RP ID
	Addr         string // VAULT_ADDR, default :8080
	DevHTTP      bool   // VAULT_DEV_HTTP=true: plain HTTP, only with VAULT_DOMAIN=localhost (local testing)
	Storage      string // VAULT_STORAGE: sqlite | postgres
	SQLitePath   string // VAULT_SQLITE_PATH
	DatabaseURL  string // VAULT_DATABASE_URL (the app login role)
	MigrateURL   string // VAULT_MIGRATE_DATABASE_URL (table owner, used only for migrations; defaults to VAULT_DATABASE_URL)
	Name         string // VAULT_NAME: optional instance name for the page header (max 32 chars)
	KeyProvider  string // VAULT_KEY_PROVIDER: manual (default) | aws-kms
	MasterKey    []byte // from VAULT_MASTER_KEY_FILE (preferred) or VAULT_MASTER_KEY
	KeyFile      string // VAULT_MASTER_KEY_FILE
	KeyGenerate  bool   // VAULT_MASTER_KEY_GENERATE=true: serve creates KeyFile when it is missing and the database has no encrypted data
	KeyMissing   bool   // KeyGenerate is on and KeyFile does not exist yet
	KMSKeyARN    string // VAULT_KMS_KEY_ARN
	OIDCClientID string // VAULT_OIDC_CLIENT_ID
	OIDCSecret   string // VAULT_OIDC_CLIENT_SECRET (or VAULT_OIDC_CLIENT_SECRET_FILE)
}

func env(k string) string { return strings.TrimSpace(os.Getenv(k)) }

// normalizeDomain accepts what people paste from a platform ("https://Vault.Example.com/") and returns the bare,
// lowercase host name; a path, port or space is not a domain.
func normalizeDomain(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	s = strings.TrimSuffix(s, "/")
	return s, s != "" && !strings.ContainsAny(s, "/: ")
}

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
		SQLitePath: env("VAULT_SQLITE_PATH"), DatabaseURL: env("VAULT_DATABASE_URL"), MigrateURL: env("VAULT_MIGRATE_DATABASE_URL"),
		KeyProvider: env("VAULT_KEY_PROVIDER"), KMSKeyARN: env("VAULT_KMS_KEY_ARN"),
		OIDCClientID: env("VAULT_OIDC_CLIENT_ID"), Name: env("VAULT_NAME"),
	}
	var errs []error
	need := func(ok bool, msg string) {
		if !ok {
			errs = append(errs, errors.New(msg))
		}
	}
	var okDomain bool
	c.Domain, okDomain = normalizeDomain(c.Domain)
	need(okDomain, "VAULT_DOMAIN must be a bare domain name, e.g. vault.example.com (a leading https:// and a trailing slash are tolerated)")
	if c.Addr == "" {
		c.Addr = defaultAddr
	}
	need(len(c.Name) <= 32 && !strings.ContainsAny(c.Name, "<>&\"'`\n\r"), "VAULT_NAME must be at most 32 characters of plain text")
	if env("VAULT_DEV_HTTP") == "true" {
		need(c.Domain == "localhost", "VAULT_DEV_HTTP=true is only allowed with VAULT_DOMAIN=localhost")
		c.DevHTTP = true
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
		c.KeyFile = env("VAULT_MASTER_KEY_FILE")
		c.KeyGenerate = env("VAULT_MASTER_KEY_GENERATE") == "true"
		need(!c.KeyGenerate || c.KeyFile != "", "VAULT_MASTER_KEY_GENERATE=true needs VAULT_MASTER_KEY_FILE")
		mk, err := fileOrEnv("VAULT_MASTER_KEY_FILE", "VAULT_MASTER_KEY")
		if c.KeyGenerate && c.KeyFile != "" {
			if _, serr := os.Stat(c.KeyFile); errors.Is(serr, fs.ErrNotExist) {
				c.KeyMissing, err = true, nil
			}
		}
		need(err == nil, "cannot read VAULT_MASTER_KEY_FILE")
		need(c.KeyMissing || strings.TrimSpace(mk) != "", "the master key is required: set VAULT_MASTER_KEY_FILE (Docker secret) or VAULT_MASTER_KEY")
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

func (c config) authConfig() auth.Config {
	return auth.Config{RPID: c.Domain, RPOrigin: c.baseURL(), Issuer: "kuukura"}
}

func (c config) dsn() string {
	if c.Storage == "sqlite" {
		return c.SQLitePath
	}
	return c.DatabaseURL
}

// scrub is err's text with the database URLs and their passwords blanked: a driver error may quote the connection
// string, and the cause belongs in the message only without credentials.
func (c config) scrub(err error) string {
	msg := err.Error()
	for _, raw := range []string{c.DatabaseURL, c.MigrateURL} {
		if raw == "" {
			continue
		}
		msg = strings.ReplaceAll(msg, raw, "<database url>")
		if u, perr := url.Parse(raw); perr == nil && u.User != nil {
			if pw, ok := u.User.Password(); ok && pw != "" {
				msg = strings.ReplaceAll(msg, pw, "***")
			}
		}
	}
	return msg
}

func (c config) migrateDSN() string {
	if c.Storage == "postgres" && c.MigrateURL != "" {
		return c.MigrateURL
	}
	return c.dsn()
}

// baseURL is the public origin: https://<domain>, or http://localhost:<port> in local dev.
func (c config) baseURL() string {
	if c.DevHTTP {
		_, port, err := net.SplitHostPort(c.Addr)
		if err != nil || port == "" {
			port = "8080"
		}
		return "http://localhost:" + port
	}
	return "https://" + c.Domain
}
