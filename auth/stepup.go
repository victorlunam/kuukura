package auth

import (
	"context"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// ---- step-up: a fresh confirmation with the account's own second step ----

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
	m, err := s.factorsOf(ctx, s.p.DB(), in.PrincipalID)
	if err != nil {
		return "", err
	}
	if !m.Passkey && !m.TOTP {
		return "", ErrNoFactor
	}
	id := random(32)
	s.stepUps.Put(id, stepUp{principal: in.PrincipalID, purpose: purpose, subject: subject})
	return id, nil
}

// StepUpMethods tells the confirmation page (and the CLI) which methods the request's account can use.
func (s *Service) StepUpMethods(ctx context.Context, id string) (Methods, error) {
	r, ok := s.stepUps.Peek(id)
	if !ok {
		return Methods{}, ErrStepUpGone
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
