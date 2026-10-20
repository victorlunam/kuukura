package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/internal/access"
	"github.com/victorlunam/kuukura/internal/auth"
)

const stepUpHeader = "X-Step-Up"

// stepUpGrant is the confirmation id the caller sent with the request, if any.
func stepUpGrant(c echo.Context) string {
	return strings.TrimSpace(c.Request().Header.Get(stepUpHeader))
}

type stepUpReq struct {
	Purpose string `json:"purpose"`
	Subject string `json:"subject"`
	Profile string `json:"profile"` // the CLI profile name, shown on the confirmation page (display only)
}

func (s *Server) stepUpStart(c echo.Context) error {
	var r stepUpReq
	if err := decode(c, &r); err != nil {
		return err
	}
	if !auth.ValidPurpose(r.Purpose) {
		return badRequest("Unknown purpose.")
	}
	if r.Subject == "" {
		return badRequest("Subject is required.")
	}
	id, m, err := s.Auth.StartStepUp(c.Request().Context(), info(c), r.Purpose, r.Subject)
	if errors.Is(err, auth.ErrNoFactor) {
		return newError("factor-required", "This account has no passkey or authenticator app set up.")
	}
	if err != nil {
		if !errors.Is(err, auth.ErrLogin) {
			s.Log.Error("step-up failed", "id", requestID(c), "err", err)
		}
		return errForbidden
	}
	link := withProfile(s.BaseURL+"/stepup?id="+id, r.Profile)
	// the CLI words its prompt from methods ("Touch ID" vs "your browser")
	return c.JSON(http.StatusCreated, map[string]any{"id": id, "url": link, "methods": m.Kinds()})
}

func (s *Server) stepUpStatus(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]bool{"done": s.Auth.StepUpDone(info(c), c.Param("id"))})
}

// stepUpErr: a confirmation that no longer exists (expired, or lost when the server restarted) is a 404 the page
// can explain ("run the command again"); every other failure stays the generic 401.
func (s *Server) stepUpErr(c echo.Context, err error) error {
	if errors.Is(err, auth.ErrStepUpGone) {
		return newError("confirmation-expired", "Run the command in your terminal again to get a new one.")
	}
	return s.denied(c, err)
}

func (s *Server) stepUpBegin(c echo.Context) error {
	o, err := s.Auth.BeginStepUp(c.Request().Context(), c.Param("id"))
	if err != nil {
		return s.stepUpErr(c, err)
	}
	return c.JSON(http.StatusOK, o)
}

// stepUpTOTP confirms a request with an authenticator code (for accounts whose second step is an app).
func (s *Server) stepUpTOTP(c echo.Context) error {
	var r codeReq
	if err := decode(c, &r); err != nil {
		return err
	}
	if err := s.Auth.FinishStepUpTOTP(c.Request().Context(), c.Param("id"), r.Code, c.RealIP()); err != nil {
		return s.stepUpErr(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (s *Server) stepUpFinish(c echo.Context) error {
	b, err := body(c)
	if err != nil {
		return err
	}
	if err := s.Auth.FinishStepUp(c.Request().Context(), c.Param("id"), b, c.RealIP()); err != nil {
		return s.stepUpErr(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

// spendStepUp spends the confirmation the request carries, if it is for this purpose and subject.
func (s *Server) spendStepUp(c echo.Context, purpose, subject string) bool {
	id := stepUpGrant(c)
	return id != "" && s.Auth.ConsumeStepUp(info(c), id, purpose, subject)
}

// withStepUp runs fn without a step-up first; if one is required and the request carries a valid grant
// for this purpose and subject, the grant is spent and fn runs again with it.
func (s *Server) withStepUp(c echo.Context, purpose, subject string, fn func(stepUp bool) error) error {
	err := fn(false)
	if !isStepUp(err) || !s.spendStepUp(c, purpose, subject) {
		return err
	}
	return fn(true)
}

func isStepUp(err error) bool {
	var de *access.Error
	return errors.As(err, &de) && de.Code == access.CodeStepUp
}

// stepUpAsk words what a confirmation is for, from its purpose and subject. The subject is the person's own
// selector (or a factor kind or id), shown as plain text: the template escapes it.
func stepUpAsk(purpose, subject string) string {
	switch purpose {
	case auth.PurposeReveal:
		return "Reveal " + subject
	case auth.PurposeRun:
		return "Run with " + subject
	case auth.PurposeAuthorizeOff:
		return "Turn off confirmation for " + subject
	case auth.PurposeFactorAdd:
		if subject == "totp" {
			return "Add an authenticator app"
		}
		return "Add a passkey"
	case auth.PurposeFactorRemove:
		return "Remove a passkey or authenticator app"
	}
	return ""
}

func (s *Server) stepUpPage(c echo.Context) error {
	id := c.QueryParam("id")
	r, err := s.Auth.LookupStepUp(c.Request().Context(), id)
	if err != nil || !r.Passkey && !r.TOTP { // unknown, expired or already used request
		return s.page(c, http.StatusNotFound, pageData{
			Title: "This confirmation is no longer valid", Mode: "fail", Art: art("alert"),
			Detail: "It may have expired or already been used. Run the command in your terminal again to get a new one.",
		})
	}
	return s.page(c, http.StatusOK, pageData{Title: "Confirm it's you", Mode: "stepup", ID: id, Art: art("confirm"),
		Label: auth.CleanLabel(c.QueryParam("profile")), HasPasskey: r.Passkey, HasTOTP: r.TOTP, Default: r.Default,
		Ask: stepUpAsk(r.Purpose, r.Subject)})
}
