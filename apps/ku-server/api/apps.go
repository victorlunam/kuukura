package api

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/internal/access"
)

type appReq struct {
	Name string `json:"name"`
}

// createApp gives the caller write access to a new app; an existing app answers 409 app-exists.
func (s *Server) createApp(c echo.Context) error {
	var r appReq
	if err := decode(c, &r); err != nil {
		return err
	}
	if err := s.Admin.CreateApp(c.Request().Context(), actor(c), r.Name); err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, map[string]string{"app": r.Name, "granted": access.Write})
}
