package api

import (
	"encoding/json"
	"io"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/internal/access"
	"github.com/victorlunam/kuukura/internal/auth"
)

func info(c echo.Context) auth.Info { in, _ := c.Get("info").(auth.Info); return in }

func actor(c echo.Context) access.Actor {
	in := info(c)
	return access.Actor{ID: in.PrincipalID, Machine: in.Machine, IP: c.RealIP()}
}

// decode reads a JSON body strictly (unknown fields are an error).
func decode(c echo.Context, v any) error {
	d := json.NewDecoder(c.Request().Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return badRequest("Malformed JSON body.")
	}
	return nil
}

func body(c echo.Context) ([]byte, error) {
	b, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return nil, badRequest("Unreadable body.")
	}
	return b, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// withProfile appends the CLI's profile name to a page link, so the pages can show it. The name is display only:
// anything that is not a safe label is dropped.
func withProfile(link, raw string) string {
	if p := auth.CleanLabel(raw); p != "" {
		link += "&profile=" + p
	}
	return link
}
