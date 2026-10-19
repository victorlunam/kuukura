package api

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/audit"
	"github.com/victorlunam/kuukura/storage"
)

type inviteReq struct {
	Email   string `json:"email"`
	Name    string `json:"name"`
	Machine bool   `json:"machine"`
}

// invite creates a person invite (link, 24 h) or a machine identity (key shown once).
func (s *Server) invite(c echo.Context) error {
	var r inviteReq
	if err := decode(c, &r); err != nil {
		return err
	}
	ctx, a := c.Request().Context(), actor(c)
	if r.Machine {
		inv, err := s.Identity.InviteMachine(ctx, a, r.Name)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusCreated, map[string]any{"token": inv.Token, "expires_at": inv.ExpiresAt})
	}
	inv, err := s.Identity.InviteHuman(ctx, a, r.Email)
	if err != nil {
		return err
	}
	link := s.BaseURL + "/invite?token=" + url.QueryEscape(inv.Token)
	return c.JSON(http.StatusCreated, map[string]any{"link": link, "expires_at": inv.ExpiresAt})
}

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

// identity disables an identity. {id} is the identity name (email or machine name).
func (s *Server) identity(c echo.Context) error {
	var r identityReq
	if err := decode(c, &r); err != nil {
		return err
	}
	if r.Status != "disabled" {
		return badRequest("status can only be set to disabled.")
	}
	name, err := url.PathUnescape(c.Param("id"))
	if err != nil {
		return errBadRequest
	}
	if err := s.Identity.Disable(c.Request().Context(), actor(c), name); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
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
	limit := 100
	if l := c.QueryParam("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
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
