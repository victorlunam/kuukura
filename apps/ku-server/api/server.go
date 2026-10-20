package api

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/victorlunam/kuukura/internal/access"
	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/auth"
	"github.com/victorlunam/kuukura/internal/identity"
	"github.com/victorlunam/kuukura/internal/secrets"
	"github.com/victorlunam/kuukura/internal/storage"
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
	Name      string // optional instance name shown in the page header (e.g. "neodev"); defaults to the host
	Log       *slog.Logger
	// TrustedProxies are public ranges (a CDN) trusted for X-Forwarded-* in addition to the private ranges.
	TrustedProxies []*net.IPNet
	Now            func() time.Time // rate limits; defaults to time.Now
}

type Server struct {
	Deps
	e      *echo.Echo
	public *limiter // unauthenticated, login, invite: 10/min per IP
	stepUp *limiter // the confirmation page and its calls: 60/min per IP (one confirmation is about 4 calls)
	authed *limiter // 300/min per token
	reveal *limiter // 10/min per principal
}

func New(d Deps) *Server {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	s := &Server{Deps: d,
		public: newLimiter(10, d.Now), stepUp: newLimiter(60, d.Now), authed: newLimiter(300, d.Now), reveal: newLimiter(10, d.Now)}
	e := echo.New()
	e.HideBanner, e.HidePort = true, true
	// Loopback and private ranges are always trusted proxies, plus the operator's. The client IP is the right-most
	// X-Forwarded-For entry that is not a trusted proxy, so a client cannot choose it by sending its own header; the
	// scheme header counts only when the direct peer is trusted, by the same rule.
	var trust []echo.TrustOption
	for _, n := range d.TrustedProxies {
		trust = append(trust, echo.TrustIPRange(n))
	}
	e.IPExtractor = echo.ExtractIPFromXFFHeader(trust...)
	e.SchemeExtractor = echo.ExtractSchemeFromHeaders(trust...)
	e.HTTPErrorHandler = s.errorHandler
	e.Use(s.requestID, s.recoverNoValues, s.secureHeaders, s.accessLog, middleware.BodyLimit("2M"))
	s.e = e
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.e }
