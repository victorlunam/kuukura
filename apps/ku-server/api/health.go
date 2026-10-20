package api

import (
	"context"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

func (s *Server) healthz(c echo.Context) error {
	ctx, cancel := context.WithTimeout(c.Request().Context(), 2*time.Second)
	defer cancel()
	if err := s.Storage.DB().PingContext(ctx); err != nil {
		return c.String(http.StatusServiceUnavailable, "unavailable")
	}
	return c.String(http.StatusOK, "ok")
}
