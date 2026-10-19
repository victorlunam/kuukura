package api

import (
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
)

// limiter is an in-process token bucket per key.
type limiter struct {
	mu      sync.Mutex
	perMin  int
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMin int, now func() time.Time) *limiter {
	return &limiter{perMin: perMin, buckets: map[string]*bucket{}, now: now}
}

// take spends a token. When the bucket is empty it reports the wait until the next one.
func (l *limiter) take(key string) (ok bool, remaining int, wait time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	if len(l.buckets) > 10000 { // sweep idle buckets
		for k, b := range l.buckets {
			if t.Sub(b.last) > 2*time.Minute {
				delete(l.buckets, k)
			}
		}
	}
	b, found := l.buckets[key]
	if !found {
		b = &bucket{tokens: float64(l.perMin), last: t}
		l.buckets[key] = b
	}
	rate := float64(l.perMin) / 60 // tokens per second
	b.tokens = math.Min(float64(l.perMin), b.tokens+t.Sub(b.last).Seconds()*rate)
	b.last = t
	if b.tokens < 1 {
		return false, 0, time.Duration((1 - b.tokens) / rate * float64(time.Second))
	}
	b.tokens--
	return true, int(b.tokens), 0
}

// limit enforces l for the key chosen by keyFn; over the limit it answers 429 problem+json.
func (s *Server) limit(l *limiter, keyFn func(echo.Context) string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ok, rem, wait := l.take(keyFn(c))
			h := c.Response().Header()
			if ok {
				h.Set("RateLimit", fmt.Sprintf("limit=%d, remaining=%d, reset=60", l.perMin, rem))
				return next(c)
			}
			secs := int(math.Ceil(wait.Seconds()))
			return &apiError{http.StatusTooManyRequests, "quota-exceeded", "Too many requests", "Slow down and try again shortly.", nil, map[string]string{
				"Retry-After":      fmt.Sprint(secs),
				"RateLimit":        fmt.Sprintf("limit=%d, remaining=0, reset=%d", l.perMin, secs),
				"RateLimit-Policy": fmt.Sprintf("%d;w=60", l.perMin),
			}}
		}
	}
}
