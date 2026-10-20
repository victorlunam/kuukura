package keys

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// Manual wraps DEKs with AES-256-GCM under a master key (KEK) held in RAM.
// The key material is a ring of versions; the highest version is active.
type Manual struct {
	ring   map[int][]byte
	active int
}

// ParseMasterKeys reads lines of `<version>:<base64 32-byte key>`. A single bare key (base64 of 32 bytes, or 64 hex
// characters) is version 1: that is the form a hosting platform can generate for an environment variable.
func ParseMasterKeys(data []byte) (*Manual, error) {
	if bare := bytes.TrimSpace(data); len(bare) > 0 && !bytes.ContainsAny(bare, ":\n") {
		var k []byte
		var err error
		switch len(bare) { // 64 hex characters are also valid base64, so the length decides
		case 44:
			k, err = base64.StdEncoding.DecodeString(string(bare))
		case 64:
			k, err = hex.DecodeString(string(bare))
		}
		if err != nil || len(k) != 32 {
			return nil, errors.New("keys: bad master key")
		}
		return &Manual{ring: map[int][]byte{1: k}, active: 1}, nil
	}
	m := &Manual{ring: map[int][]byte{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		// Errors name the line, never its content: it is key material.
		bad := fmt.Errorf("keys: bad master key file (line %d)", line)
		v, b64, ok := strings.Cut(text, ":")
		n, err := strconv.Atoi(v)
		if !ok || err != nil || n < 1 {
			return nil, bad
		}
		k, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(k) != 32 {
			return nil, bad
		}
		if _, dup := m.ring[n]; dup {
			return nil, fmt.Errorf("keys: master key file repeats version %d (line %d)", n, line)
		}
		m.ring[n] = k
		m.active = max(m.active, n)
	}
	if len(m.ring) == 0 {
		return nil, errors.New("keys: no master key")
	}
	return m, nil
}

// GenerateMasterKey returns a key file body holding one fresh version-N key.
func GenerateMasterKey(version int) ([]byte, error) {
	k := make([]byte, 32)
	rand.Read(k)
	return fmt.Appendf(nil, "%d:%s\n", version, base64.StdEncoding.EncodeToString(k)), nil
}

func (m *Manual) KeyID() string { return fmt.Sprintf("manual:v%d", m.active) }

func (m *Manual) Wrap(_ context.Context, dek, aad []byte) ([]byte, error) {
	gcm, err := newGCM(m.ring[m.active])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return gcm.Seal(nonce, nonce, dek, aad), nil // nonce || ciphertext || tag
}

func (m *Manual) Unwrap(_ context.Context, keyID string, wrapped, aad []byte) ([]byte, error) {
	n, ok := strings.CutPrefix(keyID, "manual:v")
	v, err := strconv.Atoi(n)
	key := m.ring[v]
	if !ok || err != nil || key == nil {
		return nil, ErrDecrypt
	}
	gcm, err := newGCM(key)
	if err != nil || len(wrapped) < gcm.NonceSize() {
		return nil, ErrDecrypt
	}
	dek, err := gcm.Open(nil, wrapped[:gcm.NonceSize()], wrapped[gcm.NonceSize():], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return dek, nil
}

// Ring is the key file body for every version, one `<version>:<base64>` line each, oldest first. It is key
// material: only `key show` and the key file writers may touch it.
func (m *Manual) Ring() []byte {
	var out []byte
	for _, v := range slices.Sorted(maps.Keys(m.ring)) {
		out = fmt.Appendf(out, "%d:%s\n", v, base64.StdEncoding.EncodeToString(m.ring[v]))
	}
	return out
}

// Version is the active key version.
func (m *Manual) Version() int { return m.active }
