// Package api is the HTTP layer: thin handlers over the domain facades.
package api

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/victorlunam/kuukura/access"
	"github.com/victorlunam/kuukura/auth"
)

// problem is an RFC 9457 problem+json body with a stable `code` extension
// (and `items` for the secrets/identities involved; never values).
type problem struct {
	Type     string   `json:"type"`
	Title    string   `json:"title"`
	Status   int      `json:"status"`
	Detail   string   `json:"detail,omitempty"`
	Instance string   `json:"instance"`
	Code     string   `json:"code"`
	Items    []string `json:"items,omitempty"`
}

type apiError struct {
	status int
	code   string
	title  string
	detail string
	items  []string
	header map[string]string
}

func (e *apiError) Error() string { return e.code }

var (
	errUnauthorized = &apiError{http.StatusUnauthorized, "unauthorized", "Authentication required", "Sign in with `ku login`.", nil, nil}
	errForbidden    = &apiError{http.StatusForbidden, "forbidden", "Not permitted", "", nil, nil}
	errBadRequest   = &apiError{http.StatusBadRequest, "invalid-request", "Invalid request", "", nil, nil}
)

func badRequest(detail string) *apiError {
	return &apiError{http.StatusBadRequest, "invalid-request", "Invalid request", detail, nil, nil}
}

// domainCodes maps domain error codes to HTTP status and stable problem codes.
var domainCodes = map[string]struct {
	status int
	code   string
	title  string
}{
	access.CodeNotFound:     {404, "not-found", "Not found"},
	access.CodeDenied:       {403, "forbidden", "Not permitted"},
	access.CodeAmbiguous:    {409, "ambiguous", "Several secrets match"},
	access.CodeBlocked:      {409, "blocked", "Secret is blocked"},
	access.CodeClash:        {409, "clash", "Name and tags already exist"},
	access.CodeStepUp:       {403, "step-up-required", "Confirmation required"},
	access.CodeWouldCreate:  {409, "needs-confirmation", "Secret does not exist yet"},
	access.CodeInvalid:      {400, "invalid-request", "Invalid request"},
	access.CodeNeedsOne:     {400, "needs-one", "Select exactly one secret"},
	access.CodeKindMismatch: {409, "kind-mismatch", "Different kind of secret"},
	access.CodeLastAdmin:    {409, "last-admin", "Last admin"},
	access.CodeConflict:     {409, "conflict", "Already exists"},
}

func toAPIError(err error) *apiError {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae
	}
	var de *access.Error
	if errors.As(err, &de) {
		if m, ok := domainCodes[de.Code]; ok {
			return &apiError{m.status, m.code, m.title, de.Msg, de.Items, nil}
		}
	}
	if errors.Is(err, auth.ErrLogin) || errors.Is(err, auth.ErrInvalid) {
		return errUnauthorized
	}
	var he *echo.HTTPError
	if errors.As(err, &he) {
		switch he.Code {
		case http.StatusNotFound:
			return &apiError{404, "not-found", "Not found", "", nil, nil}
		case http.StatusMethodNotAllowed:
			return &apiError{405, "method-not-allowed", "Method not allowed", "", nil, nil}
		case http.StatusRequestEntityTooLarge:
			return &apiError{413, "too-large", "Request too large", "", nil, nil}
		}
	}
	return &apiError{500, "internal", "Something went wrong", "", nil, nil}
}

// errorHandler renders every error as problem+json. Internals are never exposed.
func (s *Server) errorHandler(err error, c echo.Context) {
	if c.Response().Committed {
		return
	}
	ae := toAPIError(err)
	if ae.code == "internal" {
		s.log.Error("request failed", "id", requestID(c), "method", c.Request().Method, "path", c.Path())
	}
	for k, v := range ae.header {
		c.Response().Header().Set(k, v)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	_ = c.JSONBlob(ae.status, mustJSON(problem{
		Type: "/problems/" + ae.code, Title: ae.title, Status: ae.status, Detail: ae.detail,
		Instance: "urn:uuid:" + requestID(c), Code: ae.code, Items: ae.items,
	}))
	c.Response().Header().Set(echo.HeaderContentType, "application/problem+json")
}
