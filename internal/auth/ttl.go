package auth

import (
	"sync"
	"time"
)

// ttlStore is a small in-process map with expiry, for short-lived login state. It assumes a single server
// process: the state is lost on a restart and not shared between replicas (the pages say "start again").
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

// live returns the entry for k if it exists and has not expired. The caller holds s.mu.
func (s *ttlStore[T]) live(k string) (ttlEntry[T], bool) {
	e, ok := s.m[k]
	if !ok || !s.now().Before(e.exp) {
		return ttlEntry[T]{}, false
	}
	return e, true
}

// Take returns and removes the value (single use).
func (s *ttlStore[T]) Take(k string) (T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.live(k)
	delete(s.m, k)
	return e.v, ok
}

// Peek returns the value without removing it.
func (s *ttlStore[T]) Peek(k string) (T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.live(k)
	return e.v, ok
}

// Update replaces a live value, keeping its expiry.
func (s *ttlStore[T]) Update(k string, fn func(*T)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.live(k)
	if !ok {
		return false
	}
	fn(&e.v)
	s.m[k] = e
	return true
}
