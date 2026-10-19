package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/victorlunam/kuukura/access"
	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/auth"
	"github.com/victorlunam/kuukura/identity"
	"github.com/victorlunam/kuukura/secrets"
	"github.com/victorlunam/kuukura/storage"
)

// Deps are the facades the handlers call. Handlers never touch storage directly (except the health ping).
type Deps struct {
	Secrets   *secrets.Service
	Admin     *access.Admin
	Identity  *identity.Service
	Auth      *auth.Service
	Tokens    *auth.Tokens
	Audit     *audit.Log
	Storage   storage.Provider
	BaseURL   string // e.g. https://vault.example.com (http://localhost:8080 in local dev)
	AllowHTTP bool   // local development on localhost only
	Log       *slog.Logger
	Now       func() time.Time // rate limits; defaults to time.Now
}

type Server struct {
	Deps
	log    *slog.Logger
	e      *echo.Echo
	public *limiter // unauthenticated, login, invite: 10/min per IP
	authed *limiter // 300/min per token
	reveal *limiter // 10/min per principal
}

const stepUpHeader = "X-Step-Up"

func New(d Deps) *Server {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.New(slog.NewJSONHandler(discardWriter{}, nil))
	}
	s := &Server{Deps: d, log: d.Log,
		public: newLimiter(10, d.Now), authed: newLimiter(300, d.Now), reveal: newLimiter(10, d.Now)}
	e := echo.New()
	e.HideBanner, e.HidePort = true, true
	e.IPExtractor = echo.ExtractIPFromXFFHeader() // trusts loopback and private (proxy) ranges only
	e.HTTPErrorHandler = s.errorHandler
	e.Use(s.requestID, s.recoverNoValues, s.secureHeaders, s.accessLog, middleware.BodyLimit("2M"))
	s.e = e
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.e }

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func (s *Server) routes() {
	e := s.e
	ip := func(c echo.Context) string { return c.RealIP() }
	pub := s.limit(s.public, ip)
	e.GET("/healthz", s.healthz)

	// browser pages and the login flow (unauthenticated, 10/min per IP)
	e.GET("/invite", s.invitePage, s.httpsOnly, pub)
	e.GET("/auth/login", s.login, s.httpsOnly, pub)
	e.GET("/auth/callback", s.callback, s.httpsOnly, pub)
	e.GET("/auth/done", s.donePage, s.httpsOnly)
	e.POST("/auth/token", s.token, s.httpsOnly, pub)
	e.GET("/stepup", s.stepUpPage, s.httpsOnly, pub)
	e.POST("/stepup/:id/begin", s.stepUpBegin, s.httpsOnly, pub)
	e.POST("/stepup/:id/finish", s.stepUpFinish, s.httpsOnly, pub)

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

	api.GET("/secrets", s.listSecrets, read)
	api.POST("/secrets/versions", s.setSecret, write)
	api.POST("/secrets/reveal", s.revealSecret, read, revealLimit)
	api.PATCH("/secrets", s.patchSecrets, write)
	api.POST("/secrets/revoke", s.revokeSecrets, write)
	api.POST("/run", s.runSecrets, read)

	api.POST("/workspace/invites", s.invite, write)
	api.PATCH("/workspace/groups/:group", s.group, write)
	api.POST("/workspace/grants", s.grant, write)
	api.DELETE("/workspace/grants", s.ungrant, write)
	api.PATCH("/workspace/identities/:id", s.identity, write)
	api.GET("/workspace/audit", s.auditRows, write)
}

// ---- middleware ----

func requestID(c echo.Context) string { id, _ := c.Get("rid").(string); return id }

func (s *Server) requestID(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		id := uuid.NewString()
		c.Set("rid", id)
		c.Response().Header().Set("X-Request-ID", id)
		return next(c)
	}
}

// recoverNoValues turns panics into 500s and logs only the request id: a panic value could carry secret data.
func (s *Server) recoverNoValues(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) (err error) {
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("panic", "id", requestID(c), "path", c.Path())
				err = &apiError{500, "internal", "Something went wrong", "", nil, nil}
			}
		}()
		return next(c)
	}
}

func (s *Server) secureHeaders(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		h := c.Response().Header()
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		return next(c)
	}
}

// accessLog logs method, route pattern, status and timing. Never the query string, headers or bodies.
func (s *Server) accessLog(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()
		err := next(c)
		if err != nil {
			c.Error(err)
		}
		s.log.Info("request", "id", requestID(c), "method", c.Request().Method, "route", c.Path(),
			"status", c.Response().Status, "ms", time.Since(start).Milliseconds(), "ip", c.RealIP())
		return nil
	}
}

func (s *Server) httpsOnly(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if c.Scheme() != "https" && !s.AllowHTTP {
			return &apiError{http.StatusBadRequest, "https-required", "HTTPS required", "", nil, nil}
		}
		return next(c)
	}
}

// authenticate validates the bearer token. Every failure is the same generic 401.
func (s *Server) authenticate(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		raw, ok := strings.CutPrefix(c.Request().Header.Get("Authorization"), "Bearer ")
		if !ok {
			return errUnauthorized
		}
		in, err := s.Tokens.Validate(c.Request().Context(), raw)
		if err != nil {
			return errUnauthorized
		}
		c.Set("info", in)
		return next(c)
	}
}

func (s *Server) needScope(scope string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if !info(c).HasScope(scope) {
				return errUnauthorized
			}
			return next(c)
		}
	}
}

func info(c echo.Context) auth.Info { in, _ := c.Get("info").(auth.Info); return in }

func actor(c echo.Context) access.Actor {
	in := info(c)
	return access.Actor{ID: in.PrincipalID, Machine: in.Machine, IP: c.RealIP()}
}

// ---- helpers ----

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// decode reads a JSON body strictly (unknown fields are an error).
func decode(c echo.Context, v any) error {
	d := json.NewDecoder(c.Request().Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return badRequest("Malformed JSON body.")
	}
	return nil
}

func (s *Server) healthz(c echo.Context) error {
	ctx, cancel := context.WithTimeout(c.Request().Context(), 2*time.Second)
	defer cancel()
	if err := s.Storage.DB().PingContext(ctx); err != nil {
		return c.String(http.StatusServiceUnavailable, "unavailable")
	}
	return c.String(http.StatusOK, "ok")
}
