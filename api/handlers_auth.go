package api

import (
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/auth"
)

// login starts the provider flow. cli_* are the CLI's localhost PKCE parameters.
func (s *Server) login(c echo.Context) error {
	port, _ := strconv.Atoi(c.QueryParam("cli_port"))
	cli := auth.CLIParams{Port: port, Challenge: c.QueryParam("cli_challenge"), State: c.QueryParam("cli_state")}
	if port == 0 && c.QueryParam("cli_challenge") == "" && c.QueryParam("cli_state") == "" {
		cli = auth.CLIParams{}
	}
	cli.Profile = c.QueryParam("cli_profile") // display only; auth.StartLogin sanitizes it
	u, err := s.Auth.StartLogin(c.QueryParam("invite"), cli)
	if err != nil {
		return s.failPage(c)
	}
	return c.Redirect(http.StatusFound, u)
}

func (s *Server) callback(c echo.Context) error {
	if e := c.QueryParam("error"); e != "" { // Google reported a problem (access_denied, ...)
		s.log.Warn("login denied", "id", requestID(c), "reason", "provider_returned_error", "detail", auth.CleanLabel(strings.ToLower(e)))
		return s.failPage(c)
	}
	p, err := s.Auth.Callback(c.Request().Context(), c.QueryParam("state"), c.QueryParam("code"), c.RealIP())
	if err != nil {
		reason, detail := auth.LoginReason(err)
		s.log.Warn("login denied", "id", requestID(c), "reason", reason, "detail", detail) // codes only, no user data
		return s.loginFailedPage(c, reason, auth.LoginEmail(err))
	}
	return s.factorPage(c, p)
}

type tokenReq struct {
	Code     string `json:"code"`
	Verifier string `json:"verifier"`
}

// token trades the CLI's one-time code plus PKCE verifier for a session.
func (s *Server) token(c echo.Context) error {
	var r tokenReq
	if err := decode(c, &r); err != nil {
		return err
	}
	iss, err := s.Auth.ExchangeCode(c.Request().Context(), r.Code, r.Verifier)
	if err != nil {
		return errUnauthorized
	}
	return c.JSON(http.StatusOK, map[string]any{"token": iss.Raw, "expires_at": iss.ExpiresAt})
}

func (s *Server) logout(c echo.Context) error {
	if err := s.Auth.Logout(c.Request().Context(), info(c), c.RealIP()); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

type codeReq struct {
	Code string `json:"code"`
}

type redirectResp struct {
	Redirect      string   `json:"redirect"`
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

func (s *Server) mfaPasskeyBegin(c echo.Context) error {
	o, err := s.Auth.BeginPasskeyLogin(c.Request().Context(), info(c))
	if err != nil {
		return errUnauthorized
	}
	return c.JSON(http.StatusOK, o)
}

func body(c echo.Context) ([]byte, error) {
	b, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return nil, badRequest("Unreadable body.")
	}
	return b, nil
}

func (s *Server) mfaPasskeyFinish(c echo.Context) error {
	b, err := body(c)
	if err != nil {
		return err
	}
	r, err := s.Auth.FinishPasskeyLogin(c.Request().Context(), info(c), b, c.RealIP())
	if err != nil {
		return errUnauthorized
	}
	return c.JSON(http.StatusOK, redirectResp{Redirect: r})
}

func (s *Server) mfaTOTP(c echo.Context) error {
	var r codeReq
	if err := decode(c, &r); err != nil {
		return err
	}
	red, err := s.Auth.VerifyTOTP(c.Request().Context(), info(c), r.Code, c.RealIP())
	if err != nil {
		return errUnauthorized
	}
	return c.JSON(http.StatusOK, redirectResp{Redirect: red})
}

func (s *Server) mfaRecovery(c echo.Context) error {
	var r codeReq
	if err := decode(c, &r); err != nil {
		return err
	}
	red, err := s.Auth.VerifyRecovery(c.Request().Context(), info(c), r.Code, c.RealIP())
	if err != nil {
		return errUnauthorized
	}
	return c.JSON(http.StatusOK, redirectResp{Redirect: red})
}

func (s *Server) enrollPasskeyBegin(c echo.Context) error {
	o, err := s.Auth.BeginPasskeyRegistration(c.Request().Context(), info(c))
	if err != nil {
		return errUnauthorized
	}
	return c.JSON(http.StatusOK, o)
}

func (s *Server) enrollPasskeyFinish(c echo.Context) error {
	b, err := body(c)
	if err != nil {
		return err
	}
	r, err := s.Auth.FinishPasskeyRegistration(c.Request().Context(), info(c), b, c.RealIP())
	if err != nil {
		return errUnauthorized
	}
	return c.JSON(http.StatusOK, redirectResp{r.Redirect, r.RecoveryCodes})
}

func (s *Server) enrollTOTPBegin(c echo.Context) error {
	secret, uri, err := s.Auth.BeginTOTP(c.Request().Context(), info(c))
	if err != nil {
		return errUnauthorized
	}
	qr, err := qrSVG(uri)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]string{"secret": secret, "uri": uri, "qr": qr})
}

func (s *Server) enrollTOTPConfirm(c echo.Context) error {
	var r codeReq
	if err := decode(c, &r); err != nil {
		return err
	}
	res, err := s.Auth.ConfirmTOTP(c.Request().Context(), info(c), r.Code, c.RealIP())
	if err != nil {
		return errUnauthorized
	}
	return c.JSON(http.StatusOK, redirectResp{res.Redirect, res.RecoveryCodes})
}

// ---- step-up ----

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
	if r.Purpose != purposeReveal && r.Purpose != purposeRun && r.Purpose != purposeAuthorizeOff || r.Subject == "" {
		return badRequest("Unknown purpose.")
	}
	id, err := s.Auth.StartStepUp(info(c), r.Purpose, r.Subject)
	if err != nil {
		return errForbidden
	}
	link := s.BaseURL + "/stepup?id=" + id
	if p := auth.CleanLabel(r.Profile); p != "" {
		link += "&profile=" + p
	}
	return c.JSON(http.StatusCreated, map[string]string{"id": id, "url": link})
}

func (s *Server) stepUpStatus(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]bool{"done": s.Auth.StepUpDone(info(c), c.Param("id"))})
}

func (s *Server) stepUpBegin(c echo.Context) error {
	o, err := s.Auth.BeginStepUp(c.Request().Context(), c.Param("id"))
	if err != nil {
		return errUnauthorized
	}
	return c.JSON(http.StatusOK, o)
}

func (s *Server) stepUpFinish(c echo.Context) error {
	b, err := body(c)
	if err != nil {
		return err
	}
	if err := s.Auth.FinishStepUp(c.Request().Context(), c.Param("id"), b); err != nil {
		return errUnauthorized
	}
	return c.NoContent(http.StatusNoContent)
}

// withStepUp runs fn without a step-up first; if one is required and the request carries a valid grant
// for this purpose and subject, the grant is spent and fn runs again with it.
func (s *Server) withStepUp(c echo.Context, purpose, subject string, fn func(stepUp bool) error) error {
	err := fn(false)
	if !isStepUp(err) {
		return err
	}
	id := strings.TrimSpace(c.Request().Header.Get(stepUpHeader))
	if id == "" || !s.Auth.ConsumeStepUp(info(c), id, purpose, subject) {
		return err
	}
	return fn(true)
}
