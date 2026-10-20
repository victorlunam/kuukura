package api

import (
	"net/http"
	"net/url"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/internal/auth"
)

type inviteReq struct {
	Email   string `json:"email"`
	Name    string `json:"name"`
	Machine bool   `json:"machine"`
	Profile string `json:"profile"` // the inviter's CLI profile name: a display-only suggestion for the invitee
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
	link := withProfile(s.BaseURL+"/invite?token="+url.QueryEscape(inv.Token), r.Profile)
	return c.JSON(http.StatusCreated, map[string]any{"link": link, "expires_at": inv.ExpiresAt})
}

func (s *Server) invitePage(c echo.Context) error {
	tok := c.QueryParam("token")
	email, err := s.Tokens.PeekInvite(c.Request().Context(), tok)
	if err != nil || email == "" {
		return s.page(c, http.StatusNotFound, pageData{
			Title: "This invite is not valid", Mode: "fail", Art: art("alert"),
			Detail: "It may have expired or already been used. Ask your admin for a new one.",
		})
	}
	link := "/auth/login?go=1&invite=" + url.QueryEscape(tok)   // this page already is the button page
	if p := auth.CleanLabel(c.QueryParam("profile")); p != "" { // the inviter's profile name, carried to the "all set" page
		link += "&cli_profile=" + p
	}
	return s.page(c, http.StatusOK, pageData{
		Title: "You're invited", Mode: "invite", Art: art("vault-empty"), Step: 1,
		Email: email, Link: link,
	})
}
