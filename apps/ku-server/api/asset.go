package api

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// The static brand assets are served by name from an allow-list.
var assetNames = map[string]bool{"logo.svg": true, "mark.svg": true, "favicon.svg": true, "banner.svg": true}

// asset serves an embedded SVG. They are sandboxed by CSP in case they are opened directly.
func (s *Server) asset(c echo.Context) error {
	name := c.Param("name")
	if name == "" {
		name = "favicon.svg"
	}
	if !assetNames[name] {
		return newError("not-found", "")
	}
	h := c.Response().Header()
	h.Set("Cache-Control", "public, max-age=86400")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	return c.Blob(http.StatusOK, "image/svg+xml", []byte(brandFile("assets/"+name)))
}
