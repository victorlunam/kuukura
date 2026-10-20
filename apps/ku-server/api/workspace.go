package api

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/storage"
)

type groupReq struct {
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

func (s *Server) group(c echo.Context) error {
	var r groupReq
	if err := decode(c, &r); err != nil {
		return err
	}
	if err := s.Admin.SetMembers(c.Request().Context(), actor(c), c.Param("group"), r.Add, r.Remove); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

type grantReq struct {
	Subject    string   `json:"subject"`
	Permission string   `json:"permission"`
	Tags       []string `json:"tags"`
}

func (s *Server) grant(c echo.Context) error {
	var r grantReq
	if err := decode(c, &r); err != nil {
		return err
	}
	if err := s.Admin.Grant(c.Request().Context(), actor(c), r.Subject, r.Permission, r.Tags); err != nil {
		return err
	}
	return c.NoContent(http.StatusCreated)
}

type ungrantReq struct {
	Subject string   `json:"subject"`
	Tags    []string `json:"tags"`
}

func (s *Server) ungrant(c echo.Context) error {
	var r ungrantReq
	if err := decode(c, &r); err != nil {
		return err
	}
	if err := s.Admin.Ungrant(c.Request().Context(), actor(c), r.Subject, r.Tags); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

type identityReq struct {
	Status string `json:"status"`
}

// identity disables or enables an identity. {id} is the identity name (email or machine name). Enabling answers
// with the status the identity ends up in: a person who never finished signing up is "invited" again.
func (s *Server) identity(c echo.Context) error {
	var r identityReq
	if err := decode(c, &r); err != nil {
		return err
	}
	name, err := url.PathUnescape(c.Param("id"))
	if err != nil {
		return badRequest("Malformed identity name.")
	}
	ctx := c.Request().Context()
	switch r.Status {
	case "disabled":
		if err := s.Identity.Disable(ctx, actor(c), name); err != nil {
			return err
		}
		return c.NoContent(http.StatusNoContent)
	case "active":
		status, err := s.Identity.Enable(ctx, actor(c), name)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, map[string]string{"status": status})
	}
	return badRequest("Status can only be set to disabled or active.")
}

type auditRow struct {
	ID         string         `json:"id"`
	At         string         `json:"at"`
	Principal  string         `json:"principal"`
	Action     string         `json:"action"`
	Secret     string         `json:"secret,omitempty"`
	SecretID   string         `json:"secret_id,omitempty"`
	Version    *int           `json:"version,omitempty"`
	Result     string         `json:"result"`
	IP         string         `json:"ip,omitempty"`
	TargetType string         `json:"target_type,omitempty"`
	TargetID   string         `json:"target_id,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

func (s *Server) auditRows(c echo.Context) error {
	ctx, a := c.Request().Context(), actor(c)
	if err := s.Identity.RequireAdmin(ctx, a, "list"); err != nil {
		return err
	}
	var tags []string
	if t := c.QueryParam("tags"); t != "" {
		tags = strings.Split(t, ",")
	}
	nt, err := storage.NormalizeTags(tags)
	if err != nil {
		return badRequest(err.Error())
	}
	limit, _ := strconv.Atoi(c.QueryParam("limit")) // anything unusable falls back to the log's default
	rows, err := s.Audit.List(ctx, audit.Filter{Name: c.QueryParam("name"), Tags: nt}, limit)
	if err != nil {
		return err
	}
	out := make([]auditRow, len(rows))
	for i, r := range rows {
		out[i] = auditRow{ID: r.ID.String(), At: r.At.UTC().Format("2006-01-02T15:04:05Z"), Principal: r.PrincipalName, Action: r.Action,
			Secret: r.SecretName, Version: r.Version, Result: r.Result, IP: r.IP, TargetType: r.TargetType, Metadata: r.Metadata}
		if r.SecretID != nil {
			out[i].SecretID = r.SecretID.String()
		}
		if r.TargetID != nil {
			out[i].TargetID = r.TargetID.String()
		}
	}
	return c.JSON(http.StatusOK, map[string]any{"rows": out})
}
