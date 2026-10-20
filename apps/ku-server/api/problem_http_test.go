package api_test

import (
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

func TestProblemJSONAndTransport(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		e.problem(e.do("GET", "/secrets", "", nil), 401, "unauthorized")
		e.problem(e.do("GET", "/secrets", "ku_bogus", nil), 401, "unauthorized")
		e.problem(e.do("GET", "/nope", "", nil), 401, "unauthorized") // unknown paths do not reveal the route table
		if r := e.do("GET", "/secrets", "", nil, "X-Forwarded-Proto", "-"); r.Code != 400 || r.json()["code"] != "https-required" {
			t.Fatalf("HTTPS is required: %d %s", r.Code, r.Body)
		}
		if r := e.do("GET", "/healthz", "", nil, "X-Forwarded-Proto", "-"); r.Code != 200 || r.Body.String() != "ok" {
			t.Fatalf("healthz needs no auth and no TLS inside the container: %d %q", r.Code, r.Body)
		}
		admin, _ := e.admin()
		e.problem(e.do("POST", "/secrets/versions", admin, "{not json"), 400, "invalid-request")
		e.problem(e.do("POST", "/secrets/versions", admin, `{"name":"A","unknown":1}`), 400, "invalid-request")
		if r := e.do("GET", "/healthz", "", nil); r.Header().Get("Strict-Transport-Security") == "" || r.Header().Get("X-Request-ID") == "" {
			t.Fatal("security headers / request id")
		}
	})
}
