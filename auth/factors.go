package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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

func validTOTP(secret, code string) bool {
	ok, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	return err == nil && ok
}

// VerifyTOTP checks a 6-digit code (RFC 6238, +-1 step) and completes the login.
func (s *Service) VerifyTOTP(ctx context.Context, in Info, code, ip string) (string, error) {
	if _, err := s.requireScope(in, ScopeMFA); err != nil {
		return "", err
	}
	rows, err := s.p.DB().QueryContext(ctx, s.p.Rebind(`SELECT id, encrypted_totp_secret FROM credentials WHERE principal_id = ? AND kind = 'totp'`), in.PrincipalID)
	if err != nil {
		return "", err
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
			return "", err
		}
		creds = append(creds, c)
	}
	_ = rows.Close()
	for _, c := range creds {
		secret, err := s.openTOTP(ctx, in.PrincipalID, c.enc)
		if err == nil && validTOTP(secret, strings.TrimSpace(code)) {
			var redirect string
			err := storage.InTx(ctx, s.p, func(tx *sql.Tx) error {
				if _, err := tx.ExecContext(ctx, s.p.Rebind(`UPDATE credentials SET last_used_at = ? WHERE id = ?`), s.p.TimeArg(s.now()), c.id); err != nil {
					return err
				}
				var err error
				redirect, err = s.finish(ctx, tx, in, ip)
				return err
			})
			return redirect, err
		}
	}
	return "", s.failed(ctx, in, ip)
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
	if _, err := s.requireScope(in, ScopeEnroll); err != nil {
		return nil, err
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
	if err != nil || d.session == nil {
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
	return s.activate(ctx, in, ip, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, s.p.Rebind(`INSERT INTO credentials (id, principal_id, kind, public_key, sign_count) VALUES (?, ?, 'passkey', ?, ?)`),
			uuid.New(), in.PrincipalID, blob, int(cred.Authenticator.SignCount))
		return err
	})
}

// activate stores a new factor, activates an invited principal, issues recovery codes once, finishes login.
func (s *Service) activate(ctx context.Context, in Info, ip string, addFactor func(*sql.Tx) error) (EnrollResult, error) {
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
	if _, err := s.requireScope(in, ScopeEnroll); err != nil {
		return "", "", err
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
	if err != nil || d.totpSecret == "" || !validTOTP(d.totpSecret, strings.TrimSpace(code)) {
		return EnrollResult{}, ErrLogin
	}
	enc, err := s.sealTOTP(ctx, in.PrincipalID, d.totpSecret)
	if err != nil {
		return EnrollResult{}, err
	}
	return s.activate(ctx, in, ip, func(tx *sql.Tx) error {
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

// StartStepUp opens a step-up request for the caller. Machines can never get one.
// The returned id is a capability for the browser page and the grant for the API call.
func (s *Service) StartStepUp(in Info, purpose, subject string) (string, error) {
	if in.Machine || !in.HasScope(ScopeWrite) && !in.HasScope(ScopeRead) {
		return "", ErrLogin
	}
	id := random(32)
	s.stepUps.Put(id, stepUp{principal: in.PrincipalID, purpose: purpose, subject: subject})
	return id, nil
}

// BeginStepUp returns the passkey assertion options for the request's principal.
func (s *Service) BeginStepUp(ctx context.Context, id string) (*protocol.CredentialAssertion, error) {
	r, ok := s.stepUps.Peek(id)
	if !ok {
		return nil, ErrLogin
	}
	return s.beginAssertion(ctx, r.principal, func(sd *webauthn.SessionData) {
		s.stepUps.Update(id, func(r *stepUp) { r.session = sd })
	})
}

// FinishStepUp verifies the assertion and marks the request granted.
func (s *Service) FinishStepUp(ctx context.Context, id string, body []byte) error {
	r, ok := s.stepUps.Peek(id)
	if !ok || r.session == nil {
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
