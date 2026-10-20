package api

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

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
				s.Log.Error("panic", "id", requestID(c), "path", c.Path())
				err = newError("internal", "")
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
		s.Log.Info("request", "id", requestID(c), "method", c.Request().Method, "route", c.Path(),
			"status", c.Response().Status, "ms", time.Since(start).Milliseconds(), "ip", c.RealIP())
		return nil
	}
}

func (s *Server) httpsOnly(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if c.Scheme() != "https" && !s.AllowHTTP {
			return newError("https-required", "")
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
