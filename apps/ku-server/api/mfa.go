package api

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/internal/auth"
)

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

func (s *Server) factorPage(c echo.Context, p auth.Pending) error {
	if p.Mode == "enroll" {
		return s.page(c, http.StatusOK, pageData{Title: "Secure your account", Mode: "enroll", Token: p.Token, Art: art("passkey"), Step: 2, Label: p.Profile})
	}
	return s.page(c, http.StatusOK, pageData{Title: "Confirm it's you", Mode: "mfa", Token: p.Token, Art: art("shield"), Label: p.Profile,
		HasPasskey: p.Passkey, HasTOTP: p.TOTP, Default: p.Default})
}
