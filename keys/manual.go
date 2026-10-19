package keys

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Manual wraps DEKs with AES-256-GCM under a master key (KEK) held in RAM.
// The key material is a ring of versions; the highest version is active.
type Manual struct {
	ring   map[int][]byte
	active int
}

// ParseMasterKeys reads lines of `<version>:<base64 32-byte key>`.
func ParseMasterKeys(data []byte) (*Manual, error) {
	m := &Manual{ring: map[int][]byte{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		v, b64, ok := strings.Cut(line, ":")
		n, err := strconv.Atoi(v)
		if !ok || err != nil || n < 1 {
			return nil, errors.New("keys: bad master key file")
		}
		k, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(k) != 32 {
			return nil, errors.New("keys: bad master key file")
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
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "%d:%s\n", version, base64.StdEncoding.EncodeToString(k)), nil
}

func (m *Manual) KeyID() string { return fmt.Sprintf("manual:v%d", m.active) }

func (m *Manual) Wrap(_ context.Context, dek, aad []byte) ([]byte, error) {
	gcm, err := newGCM(m.ring[m.active])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
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
