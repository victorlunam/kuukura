package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/keys"
	"github.com/victorlunam/kuukura/storage"
)

// ErrLogin is the one error for every failed login step; it says nothing about why.
var ErrLogin = errors.New("auth: login failed")

const (
	pendingMFATTL    = 5 * time.Minute
	pendingEnrollTTL = 30 * time.Minute
	flowTTL          = 10 * time.Minute
	cliCodeTTL       = time.Minute
	stepUpWindow     = 60 * time.Second
)

// Config is the instance identity used for WebAuthn.
type Config struct {
	RPID     string // instance domain; changing it invalidates passkeys
	RPOrigin string // https://<domain>
	Issuer   string // TOTP issuer shown in authenticator apps
}

type Service struct {
	p        storage.Provider
	log      *audit.Log
	tokens   *Tokens
	provider AuthProvider
	kp       keys.KeyProvider
	wa       *webauthn.WebAuthn
	cfg      Config
	now      func() time.Time

	flows   *ttlStore[flow]
	pending *ttlStore[pendingData]
	codes   *ttlStore[cliCode]
	stepUps *ttlStore[stepUp]
	adds    *ttlStore[addReq]
}

func NewService(p storage.Provider, log *audit.Log, tokens *Tokens, prov AuthProvider, kp keys.KeyProvider, cfg Config) (*Service, error) {
	wa, err := webauthn.New(&webauthn.Config{RPID: cfg.RPID, RPDisplayName: cfg.Issuer, RPOrigins: []string{cfg.RPOrigin}})
	if err != nil {
		return nil, err
	}
	s := &Service{p: p, log: log, tokens: tokens, provider: prov, kp: kp, wa: wa, cfg: cfg, now: tokens.Now}
	now := func() time.Time { return s.now() }
	s.flows = newTTL[flow](flowTTL, now)
	s.pending = newTTL[pendingData](pendingEnrollTTL, now)
	s.codes = newTTL[cliCode](cliCodeTTL, now)
	s.stepUps = newTTL[stepUp](5*time.Minute, now)
	s.adds = newTTL[addReq](addFactorTTL, now)
	return s, nil
}

// CLIParams are the localhost-PKCE parameters of the CLI that started the login.
type CLIParams struct {
	Port      int
	Challenge string // base64url SHA-256 of the CLI's verifier
	State     string
	Profile   string // the CLI profile name, shown on the pages (display only, never trusted)
}

var labelRE = regexp.MustCompile(`^[a-z0-9._-]{1,32}$`)

// CleanLabel returns s if it is a safe profile name to display, else "".
func CleanLabel(s string) string {
	if labelRE.MatchString(s) {
		return s
	}
	return ""
}

type flow struct {
	nonce, verifier, invite string
	cli                     CLIParams
}

type pendingData struct {
	cli        CLIParams
	session    *webauthn.SessionData
	totpSecret string
	add        string // "passkey" or "totp" when this enroll session adds a factor to an active account
}

type cliCode struct {
	principal uuid.UUID
	cli       CLIParams
}

func random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing is unrecoverable
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ValidCLIParams reports whether a login may start with these CLI parameters. An invite acceptance may come
// without a CLI (the invitee logs in later with `ku login`). The sign-in page checks this before showing its button.
func ValidCLIParams(invite string, cli CLIParams) bool {
	if invite != "" && cli.Port == 0 && cli.Challenge == "" && cli.State == "" {
		return true
	}
	return cli.Port >= 1024 && cli.Port <= 65535 && len(cli.Challenge) == 43 && cli.State != "" && len(cli.State) <= 128
}

// StartLogin returns the provider URL. invite is optional (invite acceptance).
func (s *Service) StartLogin(invite string, cli CLIParams) (string, error) {
	cli.Profile = CleanLabel(cli.Profile)
	if !ValidCLIParams(invite, cli) {
		return "", ErrLogin
	}
	state, nonce, verifier := random(32), random(32), oauth2.GenerateVerifier()
	s.flows.Put(state, flow{nonce: nonce, verifier: verifier, invite: invite, cli: cli})
	return s.provider.AuthURL(state, nonce, verifier), nil
}

// Pending is a mid-login session: Mode "mfa" (verify a second factor) or "enroll" (register one).
type Pending struct {
	Token       string
	PrincipalID uuid.UUID
	Mode        string
	Profile     string // CLI profile name to display, if the CLI sent one
	// What this account can use for the second step (mode "mfa"), so the page offers only real options.
	HasPasskey, HasTOTP bool
	Add                 string // mode "add": the kind of factor being added ("passkey" or "totp")
}

// Callback handles the provider redirect. Only an invited email or an existing identity gets through.
func (s *Service) Callback(ctx context.Context, state, code, ip string) (Pending, error) {
	f, ok := s.flows.Take(state)
	if !ok {
		return Pending{}, deny("unknown_state", "") // expired, already used, or the server restarted
	}
	id, err := s.provider.Exchange(ctx, code, f.verifier, f.nonce)
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) {
			return Pending{}, deny("provider_exchange_failed", re.ErrorCode) // e.g. invalid_grant, redirect_uri_mismatch
		}
		return Pending{}, deny("provider_exchange_failed", "")
	}
	email := strings.ToLower(strings.TrimSpace(id.Email))
	if !id.EmailVerified {
		return Pending{}, deny("email_not_verified", "")
	}
	if email == "" || id.Subject == "" {
		return Pending{}, deny("missing_claims", "")
	}
	if f.invite != "" { // read before the transaction: sqlite has a single connection
		want, err := s.tokens.PeekInvite(ctx, f.invite)
		if err != nil {
			return Pending{}, deny("invite_invalid", "")
		}
		if strings.ToLower(want) != email {
			return Pending{}, denyAs("invite_email_mismatch", email)
		}
	}
	var out Pending
	var failedFor *uuid.UUID
	err = storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		var pid uuid.UUID
		var status string
		if f.invite != "" {
			var err error
			if pid, err = s.tokens.ConsumeInvite(ctx, tx, f.invite); err != nil {
				return deny("invite_invalid", "")
			}
			if err := s.bindIdentity(ctx, tx, pid, id.Subject, email); err != nil {
				return err
			}
			status = "invited"
		} else {
			err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT p.id, p.status FROM identities i JOIN principals p ON p.id = i.principal_id
				WHERE i.provider = ? AND i.subject = ?`), s.provider.Name(), id.Subject).Scan(&pid, &status)
			if errors.Is(err, sql.ErrNoRows) {
				return denyAs("no_identity_for_this_account", email) // invite-only: that account was never invited
			}
			if err != nil {
				return err
			}
			if status == "disabled" {
				failedFor = &pid
				return deny("disabled", "")
			}
		}
		scope, ttl, mode := ScopeMFA, pendingMFATTL, "mfa"
		if status == "invited" || f.invite != "" {
			scope, ttl, mode = ScopeEnroll, pendingEnrollTTL, "enroll"
		}
		iss, err := s.tokens.Issue(ctx, tx, pid, KindSession, []string{scope}, ttl)
		if err != nil {
			return err
		}
		out = Pending{Token: iss.Raw, PrincipalID: pid, Mode: mode, Profile: f.cli.Profile}
		if mode == "mfa" {
			var err error
			if out.HasPasskey, out.HasTOTP, err = s.factorsOf(ctx, tx, pid); err != nil {
				return err
			}
		}
		s.pending.Put(iss.ID.String(), pendingData{cli: f.cli})
		return nil
	})
	if err != nil {
		if failedFor != nil {
			_ = s.log.Record(ctx, audit.Entry{Principal: *failedFor, Action: "login_failed", Result: audit.ResultDenied, IP: ip})
		}
		var le *LoginError
		if errors.As(err, &le) {
			return Pending{}, le
		}
		return Pending{}, deny("internal", "")
	}
	return out, nil
}

// LoginError is ErrLogin plus a machine-readable reason for the server log. The user never sees the reason
// (it could reveal which accounts exist); operators find it in the logs.
type LoginError struct {
	Reason, Detail string
	Email          string // the Google account that tried to sign in; shown back only to the person who chose it
}

func denyAs(reason, email string) *LoginError { return &LoginError{Reason: reason, Email: email} }

func (e *LoginError) Error() string          { return ErrLogin.Error() }
func (e *LoginError) Is(target error) bool   { return target == ErrLogin }
func deny(reason, detail string) *LoginError { return &LoginError{Reason: reason, Detail: detail} }

// LoginReason returns the reason code and detail of a failed login, if there is one.
func LoginReason(err error) (reason, detail string) {
	var le *LoginError
	if errors.As(err, &le) {
		return le.Reason, le.Detail
	}
	return "", ""
}

// LoginEmail returns the Google account that tried to sign in, when the denial is about that account.
func LoginEmail(err error) string {
	var le *LoginError
	if errors.As(err, &le) {
		return le.Email
	}
	return ""
}

func (s *Service) bindIdentity(ctx context.Context, tx *sql.Tx, pid uuid.UUID, subject, email string) error {
	var owner uuid.UUID
	err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT principal_id FROM identities WHERE provider = ? AND subject = ?`), s.provider.Name(), subject).Scan(&owner)
	switch {
	case err == nil && owner == pid:
		return nil
	case err == nil:
		return deny("account_belongs_to_someone_else", "")
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	_, err = tx.ExecContext(ctx, s.p.Rebind(`INSERT INTO identities (id, principal_id, provider, subject, email) VALUES (?, ?, ?, ?, ?)`),
		uuid.New(), pid, s.provider.Name(), subject, email)
	return err
}

func (s *Service) requireScope(in Info, scope string) (pendingData, error) {
	if !in.HasScope(scope) {
		return pendingData{}, ErrLogin
	}
	d, ok := s.pending.Peek(in.TokenID.String())
	if !ok {
		return d, ErrLogin
	}
	return d, nil
}

func (s *Service) failed(ctx context.Context, in Info, ip string) error {
	_ = s.log.Record(ctx, audit.Entry{Principal: in.PrincipalID, Action: "login_failed", Result: audit.ResultDenied, IP: ip})
	return ErrLogin
}

// finish ends the pending session, audits the login and returns the CLI's localhost redirect.
func (s *Service) finish(ctx context.Context, tx *sql.Tx, in Info, ip string) (string, error) {
	d, ok := s.pending.Take(in.TokenID.String())
	if !ok {
		return "", ErrLogin
	}
	if err := s.tokens.Revoke(ctx, tx, in.TokenID); err != nil {
		return "", err
	}
	if err := s.log.Append(ctx, tx, audit.Entry{Principal: in.PrincipalID, Action: "login", IP: ip}); err != nil {
		return "", err
	}
	if d.cli.Port == 0 {
		if d.cli.Profile != "" { // the profile name the inviter suggested, for the "all set" page
			return "/auth/done?profile=" + d.cli.Profile, nil
		}
		return "/auth/done", nil
	}
	code := random(32)
	s.codes.Put(code, cliCode{in.PrincipalID, d.cli})
	q := url.Values{"code": {code}, "state": {d.cli.State}}
	return fmt.Sprintf("http://127.0.0.1:%d/callback?%s", d.cli.Port, q.Encode()), nil
}

// ExchangeCode trades the one-time code plus the CLI's PKCE verifier for a session.
func (s *Service) ExchangeCode(ctx context.Context, code, verifier string) (Issued, error) {
	c, ok := s.codes.Take(code)
	if !ok {
		return Issued{}, ErrLogin
	}
	sum := sha256.Sum256([]byte(verifier))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(c.cli.Challenge)) != 1 {
		return Issued{}, ErrLogin
	}
	var iss Issued
	err := storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		var status string
		if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT status FROM principals WHERE id = ?`), c.principal).Scan(&status); err != nil || status != "active" {
			return ErrLogin
		}
		var err error
		iss, err = s.tokens.Issue(ctx, tx, c.principal, KindSession, []string{ScopeRead, ScopeWrite}, SessionTTL)
		return err
	})
	return iss, err
}

// Logout invalidates the current session.
func (s *Service) Logout(ctx context.Context, in Info, ip string) error {
	return storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		if err := s.tokens.Revoke(ctx, tx, in.TokenID); err != nil {
			return err
		}
		return s.log.Append(ctx, tx, audit.Entry{Principal: in.PrincipalID, Action: "revoke_token", IP: ip, TargetType: "token", TargetID: &in.TokenID,
			Metadata: map[string]any{"reason": "logout"}})
	})
}
