package api

import (
	"encoding/base64"
	"net/http"
	"slices"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/internal/auth"
	"github.com/victorlunam/kuukura/internal/secrets"
	"github.com/victorlunam/kuukura/internal/storage"
)

type selectorJSON struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
	Not  []string `json:"not_tags"`
}

func (s selectorJSON) sel() secrets.Selector {
	return secrets.Selector{Name: s.Name, Tags: s.Tags, Not: s.Not}
}

// subject is the canonical selector string a step-up grant is bound to: the tags and the excluded ones (with a
// leading "~"), sorted together. ku builds the same string (subjectOf), so an exclusion is part of what is confirmed.
func (s selectorJSON) subject() string {
	t, _ := storage.NormalizeTags(s.Tags)
	n, _ := storage.NormalizeTags(s.Not)
	all := append([]string{}, t...)
	for _, x := range n {
		all = append(all, "~"+x)
	}
	slices.Sort(all)
	return strings.TrimSpace(strings.ToUpper(s.Name) + " " + strings.Join(slices.Compact(all), " "))
}

type secretInfo struct {
	Name              string   `json:"name"`
	Version           int      `json:"version"`
	Tags              []string `json:"tags"`
	Kind              string   `json:"kind"`
	RequiresAuthorize bool     `json:"requires_authorize"`
	Blocked           bool     `json:"blocked"`
}

// listSecrets never returns a value, not even masked.
func (s *Server) listSecrets(c echo.Context) error {
	var tags []string
	if t := c.QueryParam("tags"); t != "" {
		tags = strings.Split(t, ",")
	}
	var not []string
	if t := c.QueryParam("not"); t != "" {
		not = strings.Split(t, ",")
	}
	list, err := s.Secrets.List(c.Request().Context(), actor(c), secrets.Selector{Name: c.QueryParam("name"), Tags: tags, Not: not})
	if err != nil {
		return err
	}
	out := make([]secretInfo, len(list))
	for i, x := range list {
		out[i] = secretInfo{x.Name, x.Version, append([]string{}, x.Tags...), x.Kind, x.RequiresAuthorize, x.Blocked}
	}
	return c.JSON(http.StatusOK, map[string]any{"secrets": out})
}

type setReq struct {
	selectorJSON
	Kind        string `json:"kind"`
	Value       string `json:"value"`
	ValueBase64 string `json:"value_base64"`
	Filename    string `json:"filename"`
	Description string `json:"description"`
	Generate    bool   `json:"generate"`
	Create      bool   `json:"create"`
}

func (s *Server) setSecret(c echo.Context) error {
	var r setReq
	if err := decode(c, &r); err != nil {
		return err
	}
	if len(r.Not) > 0 {
		return badRequest("not_tags does not apply to a new secret.")
	}
	if r.Value != "" && r.ValueBase64 != "" {
		return badRequest("Send value or value_base64, not both.")
	}
	val := []byte(r.Value)
	if r.ValueBase64 != "" {
		var err error
		if val, err = base64.StdEncoding.DecodeString(r.ValueBase64); err != nil {
			return badRequest("value_base64 is not valid base64.")
		}
	}
	res, err := s.Secrets.Set(c.Request().Context(), actor(c), secrets.SetInput{
		Name: r.Name, Tags: r.Tags, Kind: r.Kind, Value: val, Filename: r.Filename,
		Description: r.Description, Generate: r.Generate, Create: r.Create})
	if err != nil {
		return err
	}
	st := http.StatusOK
	if res.Created {
		st = http.StatusCreated
	}
	return c.JSON(st, map[string]any{"name": res.Name, "version": res.Version, "created": res.Created})
}

type valueJSON struct {
	Name        string `json:"name"`
	Version     int    `json:"version"`
	Kind        string `json:"kind"`
	Filename    string `json:"filename,omitempty"`
	Value       string `json:"value,omitempty"`
	ValueBase64 string `json:"value_base64,omitempty"`
}

func toValueJSON(v secrets.Value) valueJSON {
	out := valueJSON{Name: v.Name, Version: v.Version, Kind: v.Kind, Filename: v.Filename}
	if v.Kind == "file" {
		out.ValueBase64 = base64.StdEncoding.EncodeToString(v.Data)
	} else {
		out.Value = string(v.Data)
	}
	return out
}

func (s *Server) revealSecret(c echo.Context) error {
	var r selectorJSON
	if err := decode(c, &r); err != nil {
		return err
	}
	var v secrets.Value
	err := s.withStepUp(c, auth.PurposeReveal, r.subject(), func(stepUp bool) error {
		var err error
		v, err = s.Secrets.Reveal(c.Request().Context(), actor(c), r.sel(), stepUp)
		return err
	})
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, toValueJSON(v))
}

func (s *Server) runSecrets(c echo.Context) error {
	var r selectorJSON
	if err := decode(c, &r); err != nil {
		return err
	}
	var vals []secrets.Value
	err := s.withStepUp(c, auth.PurposeRun, r.subject(), func(stepUp bool) error {
		var err error
		vals, err = s.Secrets.Run(c.Request().Context(), actor(c), r.sel(), stepUp)
		return err
	})
	if err != nil {
		return err
	}
	out := make([]valueJSON, len(vals))
	for i, v := range vals {
		out[i] = toValueJSON(v)
	}
	return c.JSON(http.StatusOK, map[string]any{"secrets": out})
}

type patchReq struct {
	Selector          selectorJSON `json:"selector"`
	Rename            string       `json:"rename"`
	AddTags           []string     `json:"add_tags"`
	RemoveTags        []string     `json:"remove_tags"`
	RequiresAuthorize *bool        `json:"requires_authorize"`
	Archived          *bool        `json:"archived"`
}

func (s *Server) patchSecrets(c echo.Context) error {
	var r patchReq
	if err := decode(c, &r); err != nil {
		return err
	}
	ctx := c.Request().Context()
	if r.Archived != nil {
		if !*r.Archived || r.Rename != "" || len(r.AddTags) > 0 || len(r.RemoveTags) > 0 || r.RequiresAuthorize != nil {
			return badRequest("archived can only be set to true, on its own.")
		}
		names, err := s.Secrets.Archive(ctx, actor(c), r.Selector.sel())
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, map[string]any{"updated": nonNil(names)})
	}
	ch := secrets.Change{Rename: r.Rename, AddTags: r.AddTags, RemoveTags: r.RemoveTags, Authorize: r.RequiresAuthorize}
	var names []string
	run := func(stepUp bool) error {
		var err error
		names, err = s.Secrets.Update(ctx, actor(c), r.Selector.sel(), ch, stepUp)
		return err
	}
	var err error
	if r.RequiresAuthorize != nil && !*r.RequiresAuthorize {
		err = s.withStepUp(c, auth.PurposeAuthorizeOff, r.Selector.subject(), run)
	} else {
		err = run(false)
	}
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"updated": nonNil(names)})
}

func (s *Server) revokeSecrets(c echo.Context) error {
	var r selectorJSON
	if err := decode(c, &r); err != nil {
		return err
	}
	names, err := s.Secrets.Revoke(c.Request().Context(), actor(c), r.sel())
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"revoked": nonNil(names)})
}
