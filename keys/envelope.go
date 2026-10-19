// Package keys implements envelope encryption and the KeyProvider backends.
package keys

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/google/uuid"
)

var (
	ErrSealed  = errors.New("keys: sealed")
	ErrDecrypt = errors.New("keys: cannot decrypt")
)

// KeyProvider wraps and unwraps DEKs. Wrap always uses the active key.
type KeyProvider interface {
	// KeyID identifies the active key, e.g. "manual:v2" or "aws-kms:<arn>".
	KeyID() string
	Wrap(ctx context.Context, dek, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, keyID string, wrapped, aad []byte) ([]byte, error)
}

// Payload is one encrypted secret version (the crypto columns of secret_versions).
type Payload struct {
	Ciphertext    []byte
	Nonce         []byte
	WrappedKey    []byte
	KeyID         string
	FormatVersion byte
}

// The payload AAD carries an empty key_id: the key_id changes when the master
// key rotates, and rotation must not touch the ciphertext. The key_id is bound
// by the DEK wrap AAD instead.
func payloadAAD(id uuid.UUID, number uint32) []byte {
	return AAD(PurposePayload, FormatV1, id, number, "")
}

func wrapAAD(id uuid.UUID, number uint32, keyID string) []byte {
	return AAD(PurposeWrap, FormatV1, id, number, keyID)
}

// Seal encrypts plaintext under a fresh random DEK wrapped by kp.
func Seal(ctx context.Context, kp KeyProvider, id uuid.UUID, number uint32, plaintext []byte) (Payload, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return Payload{}, err
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return Payload{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Payload{}, err
	}
	keyID := kp.KeyID()
	wrapped, err := kp.Wrap(ctx, dek, wrapAAD(id, number, keyID))
	if err != nil {
		return Payload{}, err
	}
	return Payload{
		Ciphertext:    gcm.Seal(nil, nonce, plaintext, payloadAAD(id, number)),
		Nonce:         nonce,
		WrappedKey:    wrapped,
		KeyID:         keyID,
		FormatVersion: FormatV1,
	}, nil
}

// Open decrypts a payload. Every failure is the same generic error.
func Open(ctx context.Context, kp KeyProvider, id uuid.UUID, number uint32, p Payload) ([]byte, error) {
	if p.FormatVersion != FormatV1 {
		return nil, ErrDecrypt
	}
	dek, err := kp.Unwrap(ctx, p.KeyID, p.WrappedKey, wrapAAD(id, number, p.KeyID))
	if err != nil {
		if errors.Is(err, ErrSealed) {
			return nil, ErrSealed
		}
		return nil, ErrDecrypt
	}
	gcm, err := newGCM(dek)
	if err != nil || len(p.Nonce) != gcm.NonceSize() {
		return nil, ErrDecrypt
	}
	pt, err := gcm.Open(nil, p.Nonce, p.Ciphertext, payloadAAD(id, number))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Rewrap moves the DEK to the provider's active key. The ciphertext is untouched.
func Rewrap(ctx context.Context, kp KeyProvider, id uuid.UUID, number uint32, p Payload) (Payload, error) {
	dek, err := kp.Unwrap(ctx, p.KeyID, p.WrappedKey, wrapAAD(id, number, p.KeyID))
	if err != nil {
		return Payload{}, err
	}
	keyID := kp.KeyID()
	wrapped, err := kp.Wrap(ctx, dek, wrapAAD(id, number, keyID))
	if err != nil {
		return Payload{}, err
	}
	p.WrappedKey, p.KeyID = wrapped, keyID
	return p, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// Sealed is a provider with no key: it never decrypts and says nothing more.
type Sealed struct{}

func (Sealed) KeyID() string                                        { return "" }
func (Sealed) Wrap(context.Context, []byte, []byte) ([]byte, error) { return nil, ErrSealed }
func (Sealed) Unwrap(context.Context, string, []byte, []byte) ([]byte, error) {
	return nil, ErrSealed
}
