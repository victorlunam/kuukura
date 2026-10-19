package auth

import (
	"sync"
	"time"
)

// ttlStore is a small in-process map with expiry, for short-lived login state.
// One instance per organization, so no shared store is needed.
type ttlStore[T any] struct {
	mu  sync.Mutex
	m   map[string]ttlEntry[T]
	ttl time.Duration
	now func() time.Time
}

type ttlEntry[T any] struct {
	v   T
	exp time.Time
}

func newTTL[T any](ttl time.Duration, now func() time.Time) *ttlStore[T] {
	return &ttlStore[T]{m: map[string]ttlEntry[T]{}, ttl: ttl, now: now}
}

func (s *ttlStore[T]) Put(k string, v T) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.now()
	for key, e := range s.m { // sweep
		if !t.Before(e.exp) {
			delete(s.m, key)
		}
	}
	s.m[k] = ttlEntry[T]{v, t.Add(s.ttl)}
}

// Take returns and removes the value (single use).
func (s *ttlStore[T]) Take(k string) (T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[k]
	delete(s.m, k)
	if !ok || !s.now().Before(e.exp) {
		var z T
		return z, false
	}
	return e.v, true
}

// Peek returns the value without removing it.
func (s *ttlStore[T]) Peek(k string) (T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[k]
	if !ok || !s.now().Before(e.exp) {
		var z T
		return z, false
	}
	return e.v, true
}

// Update replaces a live value, keeping its expiry.
func (s *ttlStore[T]) Update(k string, fn func(*T)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[k]
	if !ok || !s.now().Before(e.exp) {
		return false
	}
	fn(&e.v)
	s.m[k] = e
	return true
}
