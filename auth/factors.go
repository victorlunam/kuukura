package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/storage"
)

const recoveryCodeCount = 10

// ---- TOTP secrets are stored encrypted under the master key ----

func totpAAD(principal uuid.UUID) []byte { return append([]byte("kuukura-totp\x00"), principal[:]...) }

// sealTOTP encodes as len(key_id) u8 || key_id || wrapped.
func (s *Service) sealTOTP(ctx context.Context, principal uuid.UUID, secret string) ([]byte, error) {
	w, err := s.kp.Wrap(ctx, []byte(secret), totpAAD(principal))
	if err != nil {
		return nil, err
	}
	id := s.kp.KeyID()
	return append(append([]byte{byte(len(id))}, id...), w...), nil // #nosec G115 -- key ids are short
}

func (s *Service) openTOTP(ctx context.Context, principal uuid.UUID, b []byte) (string, error) {
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return "", ErrLogin
	}
	n := int(b[0])
	pt, err := s.kp.Unwrap(ctx, string(b[1:1+n]), b[1+n:], totpAAD(principal))
	return string(pt), err
}

var totpOpts = totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}

// totpStep returns the 30-second step a code belongs to if it is valid within +-1 step of now (RFC 6238).
func totpStep(secret, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	for _, off := range []time.Duration{0, -30 * time.Second, 30 * time.Second} {
		t := now.UTC().Add(off)
		want, err := totp.GenerateCodeCustom(secret, t, totpOpts)
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return t.Unix() / 30, true
		}
	}
	return 0, false
}

// consumeTOTP checks a code against the principal's authenticator apps and spends it: a code (really its 30 s
// step) works once, across login and confirmations alike, so a code seen over a shoulder or in a log is useless.
func (s *Service) consumeTOTP(ctx context.Context, principal uuid.UUID, code string) (bool, error) {
	rows, err := s.p.DB().QueryContext(ctx, s.p.Rebind(`SELECT id, encrypted_totp_secret FROM credentials WHERE principal_id = ? AND kind = 'totp'`), principal)
	if err != nil {
		return false, err
	}
	type cred struct {
		id  uuid.UUID
		enc []byte
	}
	var creds []cred
	for rows.Next() {
		var c cred
		if err := rows.Scan(&c.id, &c.enc); err != nil {
			_ = rows.Close()
			return false, err
		}
		creds = append(creds, c)
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	for _, c := range creds {
		secret, err := s.openTOTP(ctx, principal, c.enc)
		if err != nil {
			continue
		}
		step, ok := totpStep(secret, code, s.now())
		if !ok {
			continue
		}
		at := s.p.TimeArg(time.Unix(step*30, 0).UTC())
		res, err := s.p.DB().ExecContext(ctx, s.p.Rebind(`UPDATE credentials SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)`), at, c.id, at)
		if err != nil {
			return false, err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return true, nil
		}
		// a valid code, but that step was already used
	}
	return false, nil
}

// factorsOf reports which second steps an account has set up.
func (s *Service) factorsOf(ctx context.Context, q storage.Querier, principal uuid.UUID) (passkey, totp bool, err error) {
	rows, err := q.QueryContext(ctx, s.p.Rebind(`SELECT DISTINCT kind FROM credentials WHERE principal_id = ?`), principal)
	if err != nil {
		return false, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		if err := rows.Scan(&kind); err != nil {
			return false, false, err
		}
		passkey = passkey || kind == "passkey"
		totp = totp || kind == "totp"
	}
	return passkey, totp, rows.Err()
}

// VerifyTOTP checks a 6-digit code and completes the login.
func (s *Service) VerifyTOTP(ctx context.Context, in Info, code, ip string) (string, error) {
	if _, err := s.requireScope(in, ScopeMFA); err != nil {
		return "", err
	}
	ok, err := s.consumeTOTP(ctx, in.PrincipalID, code)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", s.failed(ctx, in, ip)
	}
	var redirect string
	err = storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		var err error
		redirect, err = s.finish(ctx, tx, in, ip)
		return err
	})
	return redirect, err
}

// ---- recovery codes ----

func normalizeRecovery(c string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(c))
}

func hashRecovery(c string) []byte {
	h := sha256.Sum256([]byte(normalizeRecovery(c)))
	return h[:]
}

// newRecoveryCodes stores hashes of 10 single-use codes and returns the plain codes once.
func (s *Service) newRecoveryCodes(ctx context.Context, tx *sql.Tx, principal uuid.UUID) ([]string, error) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	codes := make([]string, recoveryCodeCount)
	for i := range codes {
		raw := make([]byte, 10) // 80 bits
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		c := enc.EncodeToString(raw) // 16 chars
		codes[i] = c[:4] + "-" + c[4:8] + "-" + c[8:12] + "-" + c[12:]
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`INSERT INTO recovery_codes (id, principal_id, code_hash) VALUES (?, ?, ?)`), uuid.New(), principal, hashRecovery(codes[i])); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

// VerifyRecovery spends one recovery code and completes the login.
func (s *Service) VerifyRecovery(ctx context.Context, in Info, code, ip string) (string, error) {
	if _, err := s.requireScope(in, ScopeMFA); err != nil {
		return "", err
	}
	var redirect string
	err := storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE recovery_codes SET used_at = ? WHERE principal_id = ? AND code_hash = ? AND used_at IS NULL`),
			s.p.TimeArg(s.now()), in.PrincipalID, hashRecovery(code))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrLogin
		}
		redirect, err = s.finish(ctx, tx, in, ip)
		return err
	})
	if errors.Is(err, ErrLogin) {
		return "", s.failed(ctx, in, ip)
	}
	return redirect, err
}

// ---- passkeys ----

type waUser struct {
	id    uuid.UUID
	name  string
	creds []webauthn.Credential
}

func (u waUser) WebAuthnID() []byte                         { return u.id[:] }
func (u waUser) WebAuthnName() string                       { return u.name }
func (u waUser) WebAuthnDisplayName() string                { return u.name }
func (u waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

type storedCred struct {
	rowID uuid.UUID
	cred  webauthn.Credential
}

func (s *Service) loadUser(ctx context.Context, id uuid.UUID) (waUser, []storedCred, error) {
	u := waUser{id: id}
	if err := s.p.DB().QueryRowContext(ctx, s.p.Rebind(`SELECT name FROM principals WHERE id = ?`), id).Scan(&u.name); err != nil {
		return u, nil, err
	}
	rows, err := s.p.DB().QueryContext(ctx, s.p.Rebind(`SELECT id, public_key FROM credentials WHERE principal_id = ? AND kind = 'passkey'`), id)
	if err != nil {
		return u, nil, err
	}
	defer rows.Close()
	var stored []storedCred
	for rows.Next() {
		var c storedCred
		var blob []byte
		if err := rows.Scan(&c.rowID, &blob); err != nil {
			return u, nil, err
		}
		if err := json.Unmarshal(blob, &c.cred); err != nil {
			return u, nil, err
		}
		u.creds = append(u.creds, c.cred)
		stored = append(stored, c)
	}
	return u, stored, rows.Err()
}

var uvRequired = protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired}

// BeginPasskeyRegistration starts enrolling a passkey (enroll session).
func (s *Service) BeginPasskeyRegistration(ctx context.Context, in Info) (*protocol.CredentialCreation, error) {
	d, err := s.requireScope(in, ScopeEnroll)
	if err != nil || d.add != "" && d.add != "passkey" { // an "add a TOTP" session cannot register a passkey
		return nil, ErrLogin
	}
	u, _, err := s.loadUser(ctx, in.PrincipalID)
	if err != nil {
		return nil, err
	}
	opts, sd, err := s.wa.BeginRegistration(u, webauthn.WithAuthenticatorSelection(uvRequired))
	if err != nil {
		return nil, err
	}
	s.pending.Update(in.TokenID.String(), func(d *pendingData) { d.session = sd })
	return opts, nil
}

// EnrollResult is shown once: the login redirect and, on first enrollment, the recovery codes.
type EnrollResult struct {
	Redirect      string
	RecoveryCodes []string
}

// FinishPasskeyRegistration verifies the attestation, activates the principal and completes the login.
func (s *Service) FinishPasskeyRegistration(ctx context.Context, in Info, body []byte, ip string) (EnrollResult, error) {
	d, err := s.requireScope(in, ScopeEnroll)
	if err != nil || d.session == nil || d.add != "" && d.add != "passkey" {
		return EnrollResult{}, ErrLogin
	}
	u, _, err := s.loadUser(ctx, in.PrincipalID)
	if err != nil {
		return EnrollResult{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return EnrollResult{}, ErrLogin
	}
	cred, err := s.wa.CreateCredential(u, *d.session, parsed)
	if err != nil || !cred.Flags.UserVerified {
		return EnrollResult{}, ErrLogin
	}
	blob, err := json.Marshal(cred)
	if err != nil {
		return EnrollResult{}, err
	}
	return s.activate(ctx, in, ip, d.add, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, s.p.Rebind(`INSERT INTO credentials (id, principal_id, kind, public_key, sign_count) VALUES (?, ?, 'passkey', ?, ?)`),
			uuid.New(), in.PrincipalID, blob, int(cred.Authenticator.SignCount))
		return err
	})
}

// activate stores a new factor. During first enrollment it also activates the invited principal, issues recovery
// codes once and finishes the login. When add is set the account is already active: it only stores the factor,
// ends the short enroll session and audits the change (no login, no new recovery codes).
func (s *Service) activate(ctx context.Context, in Info, ip, add string, addFactor func(*sql.Tx) error) (EnrollResult, error) {
	if add != "" {
		err := storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
			if err := addFactor(tx); err != nil {
				return err
			}
			if err := s.tokens.Revoke(ctx, tx, in.TokenID); err != nil {
				return err
			}
			pid := in.PrincipalID
			return s.log.Append(ctx, tx, audit.Entry{Principal: pid, Action: "update", IP: ip, TargetType: "principal", TargetID: &pid,
				Metadata: map[string]any{"factor": add, "change": "added"}})
		})
		s.pending.Take(in.TokenID.String())
		return EnrollResult{Redirect: "/account/added"}, err
	}
	var res EnrollResult
	err := storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		if err := addFactor(tx); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE principals SET status = 'active' WHERE id = ? AND status = 'invited'`), in.PrincipalID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT COUNT(*) FROM recovery_codes WHERE principal_id = ?`), in.PrincipalID).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			var err error
			if res.RecoveryCodes, err = s.newRecoveryCodes(ctx, tx, in.PrincipalID); err != nil {
				return err
			}
		}
		var err error
		res.Redirect, err = s.finish(ctx, tx, in, ip)
		return err
	})
	return res, err
}

// BeginPasskeyLogin starts the passkey assertion for the second factor.
func (s *Service) BeginPasskeyLogin(ctx context.Context, in Info) (*protocol.CredentialAssertion, error) {
	if _, err := s.requireScope(in, ScopeMFA); err != nil {
		return nil, err
	}
	opts, err := s.beginAssertion(ctx, in.PrincipalID, func(sd *webauthn.SessionData) {
		s.pending.Update(in.TokenID.String(), func(d *pendingData) { d.session = sd })
	})
	return opts, err
}

func (s *Service) beginAssertion(ctx context.Context, principal uuid.UUID, keep func(*webauthn.SessionData)) (*protocol.CredentialAssertion, error) {
	u, _, err := s.loadUser(ctx, principal)
	if err != nil || len(u.creds) == 0 {
		return nil, ErrLogin
	}
	opts, sd, err := s.wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, err
	}
	keep(sd)
	return opts, nil
}

// assert verifies an assertion for a principal and records the new sign count.
func (s *Service) assert(ctx context.Context, u waUser, stored []storedCred, sd webauthn.SessionData, body []byte, tx storage.Querier) error {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return ErrLogin
	}
	cred, err := s.wa.ValidateLogin(u, sd, parsed)
	if err != nil || !cred.Flags.UserVerified {
		return ErrLogin
	}
	for _, c := range stored {
		if string(c.cred.ID) == string(cred.ID) {
			blob, _ := json.Marshal(cred)
			_, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE credentials SET public_key = ?, sign_count = ?, last_used_at = ? WHERE id = ?`),
				blob, int(cred.Authenticator.SignCount), s.p.TimeArg(s.now()), c.rowID)
			return err
		}
	}
	return ErrLogin
}

// FinishPasskeyLogin verifies the assertion and completes the login.
func (s *Service) FinishPasskeyLogin(ctx context.Context, in Info, body []byte, ip string) (string, error) {
	d, err := s.requireScope(in, ScopeMFA)
	if err != nil || d.session == nil {
		return "", ErrLogin
	}
	u, stored, err := s.loadUser(ctx, in.PrincipalID) // before the tx: sqlite has a single connection
	if err != nil {
		return "", err
	}
	var redirect string
	err = storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		if err := s.assert(ctx, u, stored, *d.session, body, tx); err != nil {
			return err
		}
		var err error
		redirect, err = s.finish(ctx, tx, in, ip)
		return err
	})
	if errors.Is(err, ErrLogin) {
		return "", s.failed(ctx, in, ip)
	}
	return redirect, err
}

// ---- TOTP enrollment ----

// BeginTOTP generates a secret for the enroll session; it is stored only after a valid code confirms it.
func (s *Service) BeginTOTP(ctx context.Context, in Info) (secret, uri string, err error) {
	d, err := s.requireScope(in, ScopeEnroll)
	if err != nil || d.add != "" && d.add != "totp" { // an "add a passkey" session cannot register an app
		return "", "", ErrLogin
	}
	u, _, err := s.loadUser(ctx, in.PrincipalID)
	if err != nil {
		return "", "", err
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.cfg.Issuer, AccountName: u.name, Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		return "", "", err
	}
	s.pending.Update(in.TokenID.String(), func(d *pendingData) { d.totpSecret = key.Secret() })
	return key.Secret(), key.URL(), nil
}

// ConfirmTOTP verifies the first code, stores the encrypted secret, activates and completes the login.
func (s *Service) ConfirmTOTP(ctx context.Context, in Info, code, ip string) (EnrollResult, error) {
	d, err := s.requireScope(in, ScopeEnroll)
	if err != nil || d.totpSecret == "" || d.add != "" && d.add != "totp" {
		return EnrollResult{}, ErrLogin
	}
	if _, ok := totpStep(d.totpSecret, code, s.now()); !ok {
		return EnrollResult{}, ErrLogin
	}
	enc, err := s.sealTOTP(ctx, in.PrincipalID, d.totpSecret)
	if err != nil {
		return EnrollResult{}, err
	}
	return s.activate(ctx, in, ip, d.add, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, s.p.Rebind(`INSERT INTO credentials (id, principal_id, kind, encrypted_totp_secret) VALUES (?, ?, 'totp', ?)`),
			uuid.New(), in.PrincipalID, enc)
		return err
	})
}

// ---- step-up (Touch ID) ----

type stepUp struct {
	principal        uuid.UUID
	purpose, subject string
	session          *webauthn.SessionData
	grantedAt        time.Time
}

// ErrStepUpGone: the confirmation request is unknown, expired, or lost in a server restart. It is still an
// ErrLogin for callers that only care that nothing was confirmed; the pages use it to say "run it again".
var ErrStepUpGone error = &stepUpGone{}

type stepUpGone struct{}

func (*stepUpGone) Error() string        { return ErrLogin.Error() }
func (*stepUpGone) Is(target error) bool { return target == ErrLogin }

// ErrNoFactor: the account has no second step set up, so it cannot confirm anything.
var ErrNoFactor = errors.New("auth: no second factor")

// StartStepUp opens a step-up request for the caller. Machines can never get one.
// The returned id is a capability for the browser page and the grant for the API call.
// The confirmation uses whatever second step the account has: a passkey, or an authenticator code.
func (s *Service) StartStepUp(ctx context.Context, in Info, purpose, subject string) (string, error) {
	if in.Machine || !in.HasScope(ScopeWrite) && !in.HasScope(ScopeRead) {
		return "", ErrLogin
	}
	passkey, totp, err := s.factorsOf(ctx, s.p.DB(), in.PrincipalID)
	if err != nil {
		return "", err
	}
	if !passkey && !totp {
		return "", ErrNoFactor
	}
	id := random(32)
	s.stepUps.Put(id, stepUp{principal: in.PrincipalID, purpose: purpose, subject: subject})
	return id, nil
}

// StepUpMethods tells the confirmation page (and the CLI) which methods the request's account can use.
func (s *Service) StepUpMethods(ctx context.Context, id string) (passkey, totp bool, err error) {
	r, ok := s.stepUps.Peek(id)
	if !ok {
		return false, false, ErrStepUpGone
	}
	return s.factorsOf(ctx, s.p.DB(), r.principal)
}

// FinishStepUpTOTP confirms a request with an authenticator code. The code is spent, like at sign-in.
func (s *Service) FinishStepUpTOTP(ctx context.Context, id, code string) error {
	r, ok := s.stepUps.Peek(id)
	if !ok {
		return ErrStepUpGone
	}
	ok, err := s.consumeTOTP(ctx, r.principal, code)
	if err != nil {
		return err
	}
	if !ok {
		return ErrLogin
	}
	s.stepUps.Update(id, func(r *stepUp) { r.grantedAt = s.now(); r.session = nil })
	return nil
}

// BeginStepUp returns the passkey assertion options for the request's principal.
func (s *Service) BeginStepUp(ctx context.Context, id string) (*protocol.CredentialAssertion, error) {
	r, ok := s.stepUps.Peek(id)
	if !ok {
		return nil, ErrStepUpGone
	}
	return s.beginAssertion(ctx, r.principal, func(sd *webauthn.SessionData) {
		s.stepUps.Update(id, func(r *stepUp) { r.session = sd })
	})
}

// FinishStepUp verifies the assertion and marks the request granted.
func (s *Service) FinishStepUp(ctx context.Context, id string, body []byte) error {
	r, ok := s.stepUps.Peek(id)
	if !ok {
		return ErrStepUpGone
	}
	if r.session == nil {
		return ErrLogin
	}
	u, stored, err := s.loadUser(ctx, r.principal)
	if err != nil {
		return err
	}
	if err := s.assert(ctx, u, stored, *r.session, body, s.p.DB()); err != nil {
		return ErrLogin
	}
	s.stepUps.Update(id, func(r *stepUp) { r.grantedAt = s.now(); r.session = nil })
	return nil
}

// StepUpDone tells the polling CLI whether the assertion happened.
func (s *Service) StepUpDone(in Info, id string) bool {
	r, ok := s.stepUps.Peek(id)
	return ok && r.principal == in.PrincipalID && !r.grantedAt.IsZero()
}

// ConsumeStepUp spends a grant: single use, within 60 s of the assertion, for the same principal, purpose and subject.
func (s *Service) ConsumeStepUp(in Info, id, purpose, subject string) bool {
	r, ok := s.stepUps.Peek(id)
	if !ok || in.Machine || r.principal != in.PrincipalID || r.purpose != purpose || r.subject != subject ||
		r.grantedAt.IsZero() || s.now().Sub(r.grantedAt) > stepUpWindow {
		return false
	}
	_, ok = s.stepUps.Take(id) // single use
	return ok
}

// RewrapTOTP moves stored TOTP secrets to the provider's active key. Returns how many were rewrapped.
func (s *Service) RewrapTOTP(ctx context.Context) (int, error) {
	n := 0
	err := storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, principal_id, encrypted_totp_secret FROM credentials WHERE kind = 'totp'`)
		if err != nil {
			return err
		}
		type item struct {
			id, principal uuid.UUID
			enc           []byte
		}
		var items []item
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.id, &it.principal, &it.enc); err != nil {
				_ = rows.Close()
				return err
			}
			items = append(items, it)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, it := range items {
			if len(it.enc) > 0 && int(it.enc[0]) < len(it.enc) && string(it.enc[1:1+int(it.enc[0])]) == s.kp.KeyID() {
				continue
			}
			secret, err := s.openTOTP(ctx, it.principal, it.enc)
			if err != nil {
				return err
			}
			enc, err := s.sealTOTP(ctx, it.principal, secret)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE credentials SET encrypted_totp_secret = ? WHERE id = ?`), enc, it.id); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// ---- managing the second factors of an active account ----

// ErrLastFactor: removing it would leave the account with no second step.
var ErrLastFactor = errors.New("auth: last second factor")

// ErrNoSuchFactor: the id is not a factor of this account (the same answer for someone else's).
var ErrNoSuchFactor = errors.New("auth: no such factor")

const addFactorTTL = 10 * time.Minute

// Factor is one second step of the caller's account. Added is the date (YYYY-MM-DD).
type Factor struct {
	ID    uuid.UUID
	Kind  string
	Added string
}

// ListFactors returns the caller's second factors, oldest first.
func (s *Service) ListFactors(ctx context.Context, in Info) ([]Factor, error) {
	rows, err := s.p.DB().QueryContext(ctx, s.p.Rebind(`SELECT id, kind, CAST(created_at AS TEXT) FROM credentials WHERE principal_id = ? ORDER BY created_at, id`), in.PrincipalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Factor
	for rows.Next() {
		var f Factor
		var at string
		if err := rows.Scan(&f.ID, &f.Kind, &at); err != nil {
			return nil, err
		}
		f.Added = at[:min(10, len(at))]
		out = append(out, f)
	}
	return out, rows.Err()
}

type addReq struct {
	principal uuid.UUID
	kind      string
}

// StartAddFactor returns the one-time capability behind the page link that adds a passkey or an authenticator
// app to the caller's account. The API checks the confirmation before calling it. Machines have no factors.
func (s *Service) StartAddFactor(in Info, kind string) (string, error) {
	if in.Machine || kind != "passkey" && kind != "totp" {
		return "", ErrLogin
	}
	id := random(32)
	s.adds.Put(id, addReq{in.PrincipalID, kind})
	return id, nil
}

// OpenAddFactor spends the link and issues a short enroll session for that one kind of factor. The account
// is already active, so the session ends after the factor is stored: no login, no new recovery codes.
func (s *Service) OpenAddFactor(ctx context.Context, id string) (Pending, error) {
	r, ok := s.adds.Take(id)
	if !ok {
		return Pending{}, ErrLogin
	}
	var out Pending
	err := storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		var status string
		if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT status FROM principals WHERE id = ?`), r.principal).Scan(&status); err != nil || status != "active" {
			return ErrLogin
		}
		iss, err := s.tokens.Issue(ctx, tx, r.principal, KindSession, []string{ScopeEnroll}, pendingEnrollTTL)
		if err != nil {
			return err
		}
		out = Pending{Token: iss.Raw, PrincipalID: r.principal, Mode: "add", Add: r.kind}
		s.pending.Put(iss.ID.String(), pendingData{add: r.kind})
		return nil
	})
	return out, err
}

// RemoveFactor deletes one of the caller's factors; the last one stays.
func (s *Service) RemoveFactor(ctx context.Context, in Info, id uuid.UUID, ip string) error {
	if in.Machine {
		return ErrLogin
	}
	return storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
		var kind string
		if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT kind FROM credentials WHERE id = ? AND principal_id = ?`), id, in.PrincipalID).Scan(&kind); errors.Is(err, sql.ErrNoRows) {
			return ErrNoSuchFactor
		} else if err != nil {
			return err
		}
		var n int
		if err := tx.QueryRowContext(ctx, s.p.Rebind(`SELECT COUNT(*) FROM credentials WHERE principal_id = ?`), in.PrincipalID).Scan(&n); err != nil {
			return err
		}
		if n <= 1 {
			return ErrLastFactor
		}
		if _, err := tx.ExecContext(ctx, s.p.Rebind(`DELETE FROM credentials WHERE id = ? AND principal_id = ?`), id, in.PrincipalID); err != nil {
			return err
		}
		pid := in.PrincipalID
		return s.log.Append(ctx, tx, audit.Entry{Principal: pid, Action: "update", IP: ip, TargetType: "principal", TargetID: &pid,
			Metadata: map[string]any{"factor": kind, "change": "removed"}})
	})
}
