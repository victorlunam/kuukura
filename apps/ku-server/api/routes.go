package api

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/internal/auth"
)

func (s *Server) routes() {
	e := s.e
	ip := func(c echo.Context) string { return c.RealIP() }
	pub := s.limit(s.public, ip)
	e.GET("/healthz", s.healthz)
	e.GET("/favicon.svg", s.asset) // brand assets are static and public (no rate limit: pages load several)
	e.GET("/assets/:name", s.asset)

	// browser pages and the login flow (unauthenticated, 10/min per IP)
	e.Match([]string{http.MethodGet, http.MethodHead}, "/", s.homePage, s.httpsOnly, pub)
	e.GET("/invite", s.invitePage, s.httpsOnly, pub)
	e.GET("/auth/login", s.login, s.httpsOnly, pub)
	e.GET("/auth/callback", s.callback, s.httpsOnly, pub)
	e.GET("/auth/done", s.donePage, s.httpsOnly)
	e.POST("/auth/token", s.token, s.httpsOnly, pub)
	e.GET("/account/add", s.addFactorPage, s.httpsOnly, pub)
	e.GET("/account/added", s.addedPage, s.httpsOnly)
	su := s.limit(s.stepUp, ip) // a person who mistypes a few codes must not lock themselves out of confirming
	e.GET("/stepup", s.stepUpPage, s.httpsOnly, su)
	e.POST("/stepup/:id/begin", s.stepUpBegin, s.httpsOnly, su)
	e.POST("/stepup/:id/finish", s.stepUpFinish, s.httpsOnly, su)
	e.POST("/stepup/:id/totp", s.stepUpTOTP, s.httpsOnly, su)

	// mid-login sessions (mfa / enroll scopes): same IP limit
	mid := e.Group("/auth", s.httpsOnly, pub, s.authenticate)
	mid.POST("/mfa/passkey/begin", s.mfaPasskeyBegin)
	mid.POST("/mfa/passkey/finish", s.mfaPasskeyFinish)
	mid.POST("/mfa/totp", s.mfaTOTP)
	mid.POST("/mfa/recovery", s.mfaRecovery)
	mid.POST("/enroll/passkey/begin", s.enrollPasskeyBegin)
	mid.POST("/enroll/passkey/finish", s.enrollPasskeyFinish)
	mid.POST("/enroll/totp/begin", s.enrollTOTPBegin)
	mid.POST("/enroll/totp/confirm", s.enrollTOTPConfirm)

	// authenticated API: 300/min per token
	api := e.Group("", s.httpsOnly, s.authenticate, s.limit(s.authed, func(c echo.Context) string { return "t:" + info(c).TokenID.String() }))
	read, write := s.needScope(auth.ScopeRead), s.needScope(auth.ScopeWrite)
	revealLimit := s.limit(s.reveal, func(c echo.Context) string { return "p:" + info(c).PrincipalID.String() })

	api.POST("/auth/logout", s.logout, read)
	api.POST("/auth/stepup", s.stepUpStart, read)
	api.GET("/auth/stepup/:id", s.stepUpStatus, read)

	api.GET("/account/factors", s.listFactors, read)
	api.POST("/account/factors", s.addFactor, write)
	api.DELETE("/account/factors/:id", s.removeFactor, write)
	api.PATCH("/account/factors/:id", s.defaultFactor, write)

	api.GET("/secrets", s.listSecrets, read)
	api.POST("/secrets/versions", s.setSecret, write)
	api.POST("/secrets/reveal", s.revealSecret, read, revealLimit)
	api.PATCH("/secrets", s.patchSecrets, write)
	api.POST("/secrets/revoke", s.revokeSecrets, write)
	api.POST("/run", s.runSecrets, read)

	api.POST("/apps", s.createApp, write)

	api.POST("/workspace/invites", s.invite, write)
	api.PATCH("/workspace/groups/:group", s.group, write)
	api.POST("/workspace/grants", s.grant, write)
	api.DELETE("/workspace/grants", s.ungrant, write)
	api.PATCH("/workspace/identities/:id", s.identity, write)
	api.GET("/workspace/audit", s.auditRows, write)
}
