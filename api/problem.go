// Package api is the HTTP layer: thin handlers over the domain facades.
package api

import (
	"errors"
	"net/http"
	"slices"

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

// problems is every code the API can answer with: kebab-case, a status and a sentence-case title. Every error the
// handlers return is built from it by newError, so this table and Codes cannot drift from what is sent.
var problems = map[string]struct {
	status int
	title  string
}{
	"unauthorized":         {http.StatusUnauthorized, "Authentication required"},
	"forbidden":            {http.StatusForbidden, "Not permitted"},
	"not-found":            {http.StatusNotFound, "Not found"},
	"method-not-allowed":   {http.StatusMethodNotAllowed, "Method not allowed"},
	"too-large":            {http.StatusRequestEntityTooLarge, "Request too large"},
	"invalid-request":      {http.StatusBadRequest, "Invalid request"},
	"https-required":       {http.StatusBadRequest, "HTTPS required"},
	"quota-exceeded":       {http.StatusTooManyRequests, "Too many requests"},
	"internal":             {http.StatusInternalServerError, "Something went wrong"},
	"ambiguous":            {http.StatusConflict, "Several secrets match"},
	"blocked":              {http.StatusConflict, "Secret is blocked"},
	"clash":                {http.StatusConflict, "Name and tags already exist"},
	"needs-confirmation":   {http.StatusConflict, "Secret does not exist yet"},
	"needs-one":            {http.StatusBadRequest, "Select exactly one secret"},
	"kind-mismatch":        {http.StatusConflict, "Different kind of secret"},
	"last-admin":           {http.StatusConflict, "Last admin"},
	"last-factor":          {http.StatusConflict, "Last factor"},
	"conflict":             {http.StatusConflict, "Already exists"},
	"step-up-required":     {http.StatusForbidden, "Confirmation required"},
	"factor-required":      {http.StatusForbidden, "No way to confirm"},
	"confirmation-expired": {http.StatusNotFound, "This confirmation expired"},
}

// Codes lists every problem code the API can return, sorted.
func Codes() []string {
	codes := make([]string, 0, len(problems))
	for c := range problems {
		codes = append(codes, c)
	}
	slices.Sort(codes)
	return codes
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

// newError builds the error for a code of the table above.
func newError(code, detail string, items ...string) *apiError {
	p := problems[code]
	return &apiError{status: p.status, code: code, title: p.title, detail: detail, items: items}
}

var (
	errUnauthorized = newError("unauthorized", "Sign in with `ku login`.")
	errForbidden    = newError("forbidden", "")
)

func badRequest(detail string) *apiError { return newError("invalid-request", detail) }

// domainCodes maps the codes of the domain packages to problem codes.
var domainCodes = map[string]string{
	access.CodeNotFound:     "not-found",
	access.CodeDenied:       "forbidden",
	access.CodeAmbiguous:    "ambiguous",
	access.CodeBlocked:      "blocked",
	access.CodeClash:        "clash",
	access.CodeStepUp:       "step-up-required",
	access.CodeWouldCreate:  "needs-confirmation",
	access.CodeInvalid:      "invalid-request",
	access.CodeNeedsOne:     "needs-one",
	access.CodeKindMismatch: "kind-mismatch",
	access.CodeLastAdmin:    "last-admin",
	access.CodeConflict:     "conflict",
	access.CodeLastFactor:   "last-factor",
}

func toAPIError(err error) *apiError {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae
	}
	var de *access.Error
	if errors.As(err, &de) {
		if code, ok := domainCodes[de.Code]; ok {
			return newError(code, de.Msg, de.Items...)
		}
	}
	if errors.Is(err, auth.ErrLogin) || errors.Is(err, auth.ErrInvalid) {
		return errUnauthorized
	}
	var he *echo.HTTPError
	if errors.As(err, &he) {
		switch he.Code {
		case http.StatusNotFound:
			return newError("not-found", "")
		case http.StatusMethodNotAllowed:
			return newError("method-not-allowed", "")
		case http.StatusRequestEntityTooLarge:
			return newError("too-large", "")
		}
	}
	return newError("internal", "")
}

// errorHandler renders every error as problem+json. Internals are never exposed to the client; the cause of a
// 500 goes to the server log (error values here never carry secret values or tokens).
func (s *Server) errorHandler(err error, c echo.Context) {
	if c.Response().Committed {
		return
	}
	ae := toAPIError(err)
	if ae.code == "internal" {
		s.Log.Error("request failed", "id", requestID(c), "method", c.Request().Method, "path", c.Path(), "err", err)
	}
	h := c.Response().Header()
	for k, v := range ae.header {
		h.Set(k, v)
	}
	h.Set("Cache-Control", "no-store")
	h.Set(echo.HeaderContentType, "application/problem+json") // before the body: the header is sent with it
	_ = c.JSONBlob(ae.status, mustJSON(problem{
		Type: "/problems/" + ae.code, Title: ae.title, Status: ae.status, Detail: ae.detail,
		Instance: "urn:uuid:" + requestID(c), Code: ae.code, Items: ae.items,
	}))
}
