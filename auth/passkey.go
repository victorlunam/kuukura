package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/storage"
)

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
		_, err := tx.ExecContext(ctx, s.p.Rebind(`INSERT INTO credentials (id, principal_id, kind, public_key, sign_count, is_default)
			VALUES (?, ?, 'passkey', ?, ?, NOT EXISTS (SELECT 1 FROM credentials WHERE principal_id = ?))`), // the first one is the default
			uuid.New(), in.PrincipalID, blob, int(cred.Authenticator.SignCount), in.PrincipalID)
		return err
	})
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
