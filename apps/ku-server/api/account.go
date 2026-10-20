package api

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/internal/access"
	"github.com/victorlunam/kuukura/internal/auth"
)

// confirmed spends the caller's confirmation for this purpose and subject, or asks for one. Machines have no
// second factors, so none of the account endpoints is theirs.
func (s *Server) confirmed(c echo.Context, purpose, subject string) error {
	if info(c).Machine {
		return errForbidden
	}
	if !s.spendStepUp(c, purpose, subject) {
		return access.Fail(access.CodeStepUp, "confirm with your passkey or authenticator app")
	}
	return nil
}

func (s *Server) listFactors(c echo.Context) error {
	if info(c).Machine {
		return errForbidden
	}
	fs, err := s.Auth.ListFactors(c.Request().Context(), info(c))
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(fs))
	for _, f := range fs {
		out = append(out, map[string]any{"id": f.ID.String(), "kind": f.Kind, "added": f.Added, "default": f.Default})
	}
	return c.JSON(http.StatusOK, map[string]any{"factors": out})
}

type addFactorReq struct {
	Kind    string `json:"kind"`
	Profile string `json:"profile"` // the CLI profile name, shown on the page (display only)
}

// addFactor confirms the caller, then returns the page link where the new factor is registered.
func (s *Server) addFactor(c echo.Context) error {
	var r addFactorReq
	if err := decode(c, &r); err != nil {
		return err
	}
	if r.Kind != "passkey" && r.Kind != "totp" {
		return badRequest("Kind must be passkey or totp.")
	}
	if err := s.confirmed(c, auth.PurposeFactorAdd, r.Kind); err != nil {
		return err
	}
	id, err := s.Auth.StartAddFactor(info(c), r.Kind)
	if err != nil {
		return errForbidden
	}
	return c.JSON(http.StatusCreated, map[string]string{"url": withProfile(s.BaseURL+"/account/add?id="+id, r.Profile)})
}

func (s *Server) removeFactor(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return access.Fail(access.CodeNotFound, "no such factor")
	}
	if err := s.confirmed(c, auth.PurposeFactorRemove, id.String()); err != nil {
		return err
	}
	switch err := s.Auth.RemoveFactor(c.Request().Context(), info(c), id, c.RealIP()); {
	case errors.Is(err, auth.ErrNoSuchFactor):
		return access.Fail(access.CodeNotFound, "no such factor")
	case errors.Is(err, auth.ErrLastFactor):
		return access.Fail(access.CodeLastFactor, "this is your only passkey or authenticator app; add another one first")
	case err != nil:
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// addFactorPage is the one-time link from `ku account factor add`. Like the sign-in link it first shows a card:
// only its button (go=1) spends the link, so a link preview or prefetch cannot burn it.
func (s *Server) addFactorPage(c echo.Context) error {
	if c.QueryParam("go") == "" {
		link := withProfile("/account/add?id="+url.QueryEscape(c.QueryParam("id"))+"&go=1", c.QueryParam("profile"))
		return s.page(c, http.StatusOK, pageData{Title: "Add a passkey or authenticator app", Mode: "addask", Link: link, Art: art("passkey"), Label: auth.CleanLabel(c.QueryParam("profile"))})
	}
	p, err := s.Auth.OpenAddFactor(c.Request().Context(), c.QueryParam("id"))
	if err != nil {
		if !errors.Is(err, auth.ErrLogin) {
			s.Log.Error("add factor failed", "id", requestID(c), "err", err)
		}
		return s.page(c, http.StatusNotFound, pageData{
			Title: "This link is no longer valid", Mode: "fail", Art: art("alert"),
			Detail: "It works once and expires after 10 minutes. Run the command in your terminal again to get a new one.",
		})
	}
	return s.page(c, http.StatusOK, pageData{Title: "Add a passkey or authenticator app", Mode: "add", Token: p.Token, Add: p.Add, Art: art("passkey"),
		Label: auth.CleanLabel(c.QueryParam("profile"))})
}

func (s *Server) addedPage(c echo.Context) error {
	return s.page(c, http.StatusOK, pageData{Title: "Added", Mode: "added", Art: art("done")})
}

type defaultFactorReq struct {
	Default bool `json:"default"`
}

// defaultFactor marks one of the caller's factors as the default. It only changes which method the pages offer
// first, so it needs no confirmation.
func (s *Server) defaultFactor(c echo.Context) error {
	var r defaultFactorReq
	if err := decode(c, &r); err != nil {
		return err
	}
	if info(c).Machine {
		return errForbidden
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil || !r.Default {
		return badRequest(`Send {"default": true} for one of your factors.`)
	}
	switch err := s.Auth.SetDefaultFactor(c.Request().Context(), info(c), id, c.RealIP()); {
	case errors.Is(err, auth.ErrNoSuchFactor):
		return access.Fail(access.CodeNotFound, "no such factor")
	case err != nil:
		return err
	}
	return c.NoContent(http.StatusNoContent)
}
