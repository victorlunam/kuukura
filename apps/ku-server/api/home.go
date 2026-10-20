package api

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// homePage answers a browser that opens the server's address. It says what this is and how to connect the CLI,
// and shows nothing about accounts or secrets, so it needs no sign-in.
func (s *Server) homePage(c echo.Context) error {
	return s.page(c, http.StatusOK, pageData{Title: "kuukura server", Mode: "home", Art: art("vault-empty")})
}

// httpsPage replaces the https-required problem for a person who typed the address in a browser: the problem+json
// would be unreadable there. It stays a 400, not a redirect: behind a proxy that ends TLS without sending
// X-Forwarded-Proto a redirect to https would loop forever.
func (s *Server) httpsPage(c echo.Context) error {
	return s.page(c, http.StatusBadRequest, pageData{Title: "HTTPS required", Mode: "https", Art: art("alert")})
}

// wantsPage tells a browser navigation from the CLI and other API clients, which keep the JSON problem.
func wantsPage(c echo.Context) bool {
	r := c.Request()
	return r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html")
}
