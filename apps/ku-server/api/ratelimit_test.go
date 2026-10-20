package api_test

import (
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

func TestRateLimits(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setup(t, p)
		pin := "IP"
		ip := "203.0.113.7"
		for i := range 10 {
			if r := e.do("POST", "/auth/token", "", map[string]string{"code": "x", "verifier": "y"}, pin, ip); r.Code != 401 {
				t.Fatalf("request %d: %d", i, r.Code)
			}
		}
		r := e.do("POST", "/auth/token", "", map[string]string{"code": "x", "verifier": "y"}, pin, ip)
		e.problem(r, 429, "quota-exceeded")
		if r.Header().Get("Retry-After") == "" || !strings.Contains(r.Header().Get("RateLimit"), "remaining=0") {
			t.Fatalf("headers: %v", r.Header())
		}
		// another IP is unaffected
		if r := e.do("POST", "/auth/token", "", map[string]string{"code": "x", "verifier": "y"}, pin, "203.0.113.8"); r.Code != 401 {
			t.Fatal("limits are per IP")
		}
		// the bucket refills with time
		e.clock.Add(61)
		if r := e.do("POST", "/auth/token", "", map[string]string{"code": "x", "verifier": "y"}, pin, ip); r.Code != 401 {
			t.Fatalf("after a minute: %d", r.Code)
		}

		// reveal: 10/min per principal
		admin, _ := e.admin()
		user, _ := e.member(admin, "dev@example.test")
		for i := range 10 {
			if r := e.do("POST", "/secrets/reveal", user, map[string]any{"name": "NOPE"}); r.Code == 429 {
				t.Fatalf("reveal %d limited too early", i)
			}
		}
		e.problem(e.do("POST", "/secrets/reveal", user, map[string]any{"name": "NOPE"}), 429, "quota-exceeded")
		if r := e.do("GET", "/secrets", user, nil); r.Code != 200 {
			t.Fatalf("other endpoints keep working: %d", r.Code)
		}
	})
}
