package api

import (
	"errors"
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
	cli.Profile = auth.CleanLabel(c.QueryParam("cli_profile")) // display only
	invite := c.QueryParam("invite")
	if !auth.ValidCLIParams(invite, cli) {
		return s.failPage(c)
	}
	// Opening the link from the terminal shows the sign-in card first; only the button (go=1) goes to Google.
	// A page that merely loads never starts a login.
	if c.QueryParam("go") == "" {
		return s.signInPage(c, cli.Profile, "/auth/login?"+c.QueryString()+"&go=1")
	}
	u, err := s.Auth.StartLogin(invite, cli)
	if err != nil {
		return s.failPage(c)
	}
	return c.Redirect(http.StatusFound, u)
}

func (s *Server) callback(c echo.Context) error {
	if e := c.QueryParam("error"); e != "" { // Google reported a problem (access_denied, ...)
		s.Log.Warn("login denied", "id", requestID(c), "reason", "provider_returned_error", "detail", auth.CleanLabel(strings.ToLower(e)))
		return s.failPage(c)
	}
	p, err := s.Auth.Callback(c.Request().Context(), c.QueryParam("state"), c.QueryParam("code"), c.RealIP())
	if err != nil {
		reason, detail := auth.LoginReason(err)
		s.Log.Warn("login denied", "id", requestID(c), "reason", reason, "detail", detail) // codes only, no user data
		return s.loginFailedPage(c, reason, auth.LoginEmail(err))
	}
	return s.factorPage(c, p)
}

// denied answers a failed login or confirmation step with the generic 401. An ordinary failure (ErrLogin) is
// already in the audit log; anything else is a broken dependency, and the operator needs its cause.
func (s *Server) denied(c echo.Context, err error) error {
	if !errors.Is(err, auth.ErrLogin) {
		s.Log.Error("login step failed", "id", requestID(c), "route", c.Path(), "err", err)
	}
	return errUnauthorized
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
		return s.denied(c, err)
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
		return s.denied(c, err)
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
		return s.denied(c, err)
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
		return s.denied(c, err)
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
		return s.denied(c, err)
	}
	return c.JSON(http.StatusOK, redirectResp{Redirect: red})
}

func (s *Server) enrollPasskeyBegin(c echo.Context) error {
	o, err := s.Auth.BeginPasskeyRegistration(c.Request().Context(), info(c))
	if err != nil {
		return s.denied(c, err)
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
		return s.denied(c, err)
	}
	return c.JSON(http.StatusOK, redirectResp{r.Redirect, r.RecoveryCodes})
}

func (s *Server) enrollTOTPBegin(c echo.Context) error {
	secret, uri, err := s.Auth.BeginTOTP(c.Request().Context(), info(c))
	if err != nil {
		return s.denied(c, err)
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
		return s.denied(c, err)
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
	switch r.Purpose {
	case purposeReveal, purposeRun, purposeAuthorizeOff, purposeFactorAdd, purposeFactorRemove:
	default:
		return badRequest("Unknown purpose.")
	}
	if r.Subject == "" {
		return badRequest("Subject is required.")
	}
	id, m, err := s.Auth.StartStepUp(c.Request().Context(), info(c), r.Purpose, r.Subject)
	if errors.Is(err, auth.ErrNoFactor) {
		return &apiError{http.StatusForbidden, "second-factor-required", "No way to confirm",
			"This account has no passkey or authenticator app set up.", nil, nil}
	}
	if err != nil {
		if !errors.Is(err, auth.ErrLogin) {
			s.Log.Error("step-up failed", "id", requestID(c), "err", err)
		}
		return errForbidden
	}
	link := s.BaseURL + "/stepup?id=" + id
	if p := auth.CleanLabel(r.Profile); p != "" {
		link += "&profile=" + p
	}
	var methods []string // the CLI words its prompt from this ("Touch ID" vs "your browser"); the default comes first
	if m.Passkey {
		methods = append(methods, "passkey")
	}
	if m.TOTP {
		methods = append(methods, "totp")
	}
	if m.Default == "totp" && len(methods) == 2 {
		methods[0], methods[1] = methods[1], methods[0]
	}
	return c.JSON(http.StatusCreated, map[string]any{"id": id, "url": link, "methods": methods})
}

func (s *Server) stepUpStatus(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]bool{"done": s.Auth.StepUpDone(info(c), c.Param("id"))})
}

// stepUpErr: a confirmation that no longer exists (expired, or lost when the server restarted) is a 404 the page
// can explain ("run the command again"); every other failure stays the generic 401.
func (s *Server) stepUpErr(c echo.Context, err error) error {
	if errors.Is(err, auth.ErrStepUpGone) {
		return &apiError{http.StatusNotFound, "confirmation-expired", "This confirmation expired",
			"Run the command in your terminal again to get a new one.", nil, nil}
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

// withStepUp runs fn without a step-up first; if one is required and the request carries a valid grant
// for this purpose and subject, the grant is spent and fn runs again with it.
func (s *Server) withStepUp(c echo.Context, purpose, subject string, fn func(stepUp bool) error) error {
	err := fn(false)
	if !isStepUp(err) {
		return err
	}
	id := stepUpGrant(c)
	if id == "" || !s.Auth.ConsumeStepUp(info(c), id, purpose, subject) {
		return err
	}
	return fn(true)
}
