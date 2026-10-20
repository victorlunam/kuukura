package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/audit"
)

// ---- step-up: a fresh confirmation with the account's own second step ----

// What a confirmation can be for. A grant is bound to one purpose and one subject (a selector, a factor kind or a
// factor id).
const (
	PurposeReveal       = "reveal" // `get --reveal` and `get --out`
	PurposeRun          = "run"
	PurposeAuthorizeOff = "authorize_off"
	PurposeFactorAdd    = "factor_add"    // subject: "passkey" or "totp"
	PurposeFactorRemove = "factor_remove" // subject: the credential id
)

// ValidPurpose reports whether p is one of the purposes above.
func ValidPurpose(p string) bool {
	switch p {
	case PurposeReveal, PurposeRun, PurposeAuthorizeOff, PurposeFactorAdd, PurposeFactorRemove:
		return true
	}
	return false
}

type stepUp struct {
	principal        uuid.UUID
	purpose, subject string
	session          *webauthn.SessionData
	grantedAt        time.Time
}

// ErrStepUpGone: the confirmation request is unknown, expired, or lost in a server restart. It is still an
// ErrLogin for callers that only care that nothing was confirmed; the pages use it to say "run it again".
var ErrStepUpGone = fmt.Errorf("auth: confirmation expired: %w", ErrLogin)

// ErrNoFactor: the account has no second step set up, so it cannot confirm anything.
var ErrNoFactor = errors.New("auth: no second factor")

// StartStepUp opens a step-up request for the caller and returns its id with the methods the account can use.
// Machines can never get one. The id is a capability for the browser page and the grant for the API call.
// The confirmation uses whatever second step the account has: a passkey, or an authenticator code.
func (s *Service) StartStepUp(ctx context.Context, in Info, purpose, subject string) (string, Methods, error) {
	if in.Machine || !in.HasScope(ScopeWrite) && !in.HasScope(ScopeRead) {
		return "", Methods{}, ErrLogin
	}
	m, err := s.factorsOf(ctx, s.p.DB(), in.PrincipalID)
	if err != nil {
		return "", Methods{}, err
	}
	if !m.Passkey && !m.TOTP {
		return "", Methods{}, ErrNoFactor
	}
	id := random(32)
	s.stepUps.Put(id, stepUp{principal: in.PrincipalID, purpose: purpose, subject: subject})
	return id, m, nil
}

// StepUpRequest is what the confirmation page shows: what is being confirmed and with which methods.
type StepUpRequest struct {
	Methods
	Purpose, Subject string
}

// LookupStepUp tells the confirmation page what the request is for and which methods its account can use.
func (s *Service) LookupStepUp(ctx context.Context, id string) (StepUpRequest, error) {
	r, ok := s.stepUps.Peek(id)
	if !ok {
		return StepUpRequest{}, ErrStepUpGone
	}
	m, err := s.factorsOf(ctx, s.p.DB(), r.principal)
	return StepUpRequest{Methods: m, Purpose: r.purpose, Subject: r.subject}, err
}

// stepUpDenied audits a failed confirmation for the request's principal as a failed sign-in (the audit actions
// are a closed list); the metadata tells the two apart.
func (s *Service) stepUpDenied(ctx context.Context, r stepUp, ip string) error {
	_ = s.log.Record(ctx, audit.Entry{Principal: r.principal, Action: "login_failed", Result: audit.ResultDenied, IP: ip,
		Metadata: map[string]any{"step": "confirmation", "purpose": r.purpose}})
	return ErrLogin
}

// FinishStepUpTOTP confirms a request with an authenticator code. The code is spent, like at sign-in.
func (s *Service) FinishStepUpTOTP(ctx context.Context, id, code, ip string) error {
	r, ok := s.stepUps.Peek(id)
	if !ok {
		return ErrStepUpGone
	}
	ok, err := s.consumeTOTP(ctx, r.principal, code)
	if err != nil {
		return err
	}
	if !ok {
		return s.stepUpDenied(ctx, r, ip)
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
func (s *Service) FinishStepUp(ctx context.Context, id string, body []byte, ip string) error {
	r, ok := s.stepUps.Peek(id)
	if !ok {
		return ErrStepUpGone
	}
	if r.session == nil {
		return s.stepUpDenied(ctx, r, ip)
	}
	u, stored, err := s.loadUser(ctx, r.principal)
	if err != nil {
		return err
	}
	cloned, err := s.assert(ctx, u, stored, *r.session, body, s.p.DB())
	if errors.Is(err, ErrLogin) {
		return s.stepUpDenied(ctx, r, ip)
	}
	if err != nil {
		return err
	}
	if cloned {
		s.auditClone(ctx, r.principal, ip)
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
