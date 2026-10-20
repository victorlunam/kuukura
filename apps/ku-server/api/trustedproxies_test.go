package api_test

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

func cidrs(t *testing.T, list ...string) []*net.IPNet {
	t.Helper()
	var out []*net.IPNet
	for _, s := range list {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

// via sends one request straight from peer (the TCP address the server sees) with the given forwarding headers and
// returns the status and the client IP the access log recorded.
func (e *env) via(path, peer, xff, proto string) (int, string) {
	e.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Accept", "application/json")
	req.RemoteAddr = peer + ":4321"
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	if proto != "" {
		req.Header.Set("X-Forwarded-Proto", proto)
	}
	rec := httptest.NewRecorder()
	e.logs.Reset()
	e.srv.Handler().ServeHTTP(rec, req)
	var line struct{ IP string }
	if err := json.NewDecoder(bytes.NewReader(e.logs.Bytes())).Decode(&line); err != nil {
		e.t.Fatalf("access log: %v: %s", err, e.logs)
	}
	return rec.Code, line.IP
}

func TestClientIPBehindProxies(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		plain := setup(t, p)
		cf := setupTrusting(t, p, cidrs(t, "104.16.0.0/13", "2606:4700::/32", "203.0.113.0/24")...)
		const (
			client = "198.51.100.7"
			edge   = "104.22.1.1"  // a Cloudflare edge address
			other  = "192.0.2.50"  // public, not Cloudflare
			custom = "203.0.113.9" // listed by the operator next to cloudflare
		)
		for _, tc := range []struct {
			name, peer, xff string
			plain, trusted  string
		}{
			// client -> Cloudflare -> ALB -> Traefik (the peer); the ALB appends the Cloudflare address, Traefik the ALB's
			{"cloudflare chain", "10.0.0.2", client + ", " + edge + ", 10.1.2.3", edge, client},
			{"chain without the ALB hop", "10.0.0.2", client + ", " + edge, edge, client},
			{"ipv6 client", "10.0.0.2", "2001:db8::7, " + edge, edge, "2001:db8::7"},
			{"ipv6 edge", "10.0.0.2", client + ", 2606:4700::1", "2606:4700::1", client},
			{"cloudflare as the direct peer", edge, client, edge, client},
			{"mixed with a custom range", "10.0.0.2", client + ", " + custom + ", " + edge, edge, client},
			{"no header: the peer", "10.0.0.2", "", "10.0.0.2", "10.0.0.2"},
			// a client that reaches the server directly cannot choose its IP
			{"forged header from a direct client", other, "1.2.3.4", other, other},
			{"forged header from a direct Cloudflare-looking client", other, "1.2.3.4, " + edge, other, other},
			// a client forges a leading entry in front of the real chain: the right-most untrusted entry still wins
			{"forged entry ahead of the chain", "10.0.0.2", "1.2.3.4, " + client + ", " + edge, edge, client},
			{"garbage entry", "10.0.0.2", "not-an-ip, " + edge, edge, "10.0.0.2"}, // unparsable entries are never believed
		} {
			if _, ip := plain.via("/healthz", tc.peer, tc.xff, "https"); ip != tc.plain {
				t.Errorf("%s, Cloudflare not trusted: ip %q, want %q", tc.name, ip, tc.plain)
			}
			if _, ip := cf.via("/healthz", tc.peer, tc.xff, "https"); ip != tc.trusted {
				t.Errorf("%s, Cloudflare trusted: ip %q, want %q", tc.name, ip, tc.trusted)
			}
		}
	})
}

func TestForwardedProtoNeedsATrustedPeer(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		plain := setup(t, p)
		cf := setupTrusting(t, p, cidrs(t, "104.16.0.0/13")...)
		for _, tc := range []struct {
			name, peer, proto string
			plain, trusted    int
		}{
			{"private proxy says https", "10.0.0.2", "https", 200, 200},
			{"private proxy says http", "10.0.0.2", "http", 400, 400},
			{"Cloudflare edge says https", "104.22.1.1", "https", 400, 200},
			{"direct client claims https", "192.0.2.50", "https", 400, 400},
			{"no header", "10.0.0.2", "", 400, 400},
		} {
			if code, _ := plain.via("/", tc.peer, "", tc.proto); code != tc.plain {
				t.Errorf("%s, Cloudflare not trusted: %d, want %d", tc.name, code, tc.plain)
			}
			if code, _ := cf.via("/", tc.peer, "", tc.proto); code != tc.trusted {
				t.Errorf("%s, Cloudflare trusted: %d, want %d", tc.name, code, tc.trusted)
			}
		}
	})
}

// The extracted address is what reaches the audit log and the per-IP limit, not the edge's.
func TestAuditRecordsTheExtractedIP(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setupTrusting(t, p, cidrs(t, "104.16.0.0/13")...)
		admin, _ := e.admin()
		req := httptest.NewRequest(http.MethodPost, "/workspace/invites", strings.NewReader(`{"email":"dev@example.test"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+admin)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-For", "198.51.100.7, 104.22.1.1, 10.1.2.3")
		req.RemoteAddr = "10.0.0.2:1234"
		rec := httptest.NewRecorder()
		e.srv.Handler().ServeHTTP(rec, req)
		if rec.Code != 201 {
			t.Fatalf("invite: %d %s", rec.Code, rec.Body)
		}
		rows, err := e.log.List(t.Context(), audit.Filter{}, 1)
		if err != nil || len(rows) != 1 {
			t.Fatalf("audit rows: %v %v", rows, err)
		}
		if rows[0].IP != "198.51.100.7" {
			t.Fatalf("audit IP %q, want the client's", rows[0].IP)
		}
	})
}

func TestRateLimitIsPerClientBehindTheEdge(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		e := setupTrusting(t, p, cidrs(t, "104.16.0.0/13")...)
		for range 10 {
			e.via("/", "10.0.0.2", "198.51.100.7, 104.22.1.1", "https")
		}
		if code, _ := e.via("/", "10.0.0.2", "198.51.100.7, 104.22.1.1", "https"); code != 429 {
			t.Fatalf("the eleventh request of one client: %d", code)
		}
		if code, _ := e.via("/", "10.0.0.2", "198.51.100.8, 104.22.1.1", "https"); code != 200 {
			t.Fatalf("another client behind the same edge must not share the limit: %d", code)
		}
	})
}
