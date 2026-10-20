// Package authtest is a software WebAuthn authenticator for tests.
package authtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// Authenticator is a software passkey device for tests: it answers WebAuthn
// registration and assertion requests like a platform authenticator would.
type Authenticator struct {
	RPID, Origin string
	key          *ecdsa.PrivateKey
	credID       []byte
	count        uint32
}

// Rewind sets the sign count back to zero, like a copy of the key that lags behind the original.
func (a *Authenticator) Rewind() { a.count = 0 }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *Authenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.Origin})
	return b
}

// Register answers a creation request (opts is the JSON of the CredentialCreation).
func (a *Authenticator) Register(t *testing.T, opts json.RawMessage, uv bool) []byte {
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(opts, &o); err != nil {
		t.Fatal(err)
	}
	if a.key == nil {
		a.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		a.credID = make([]byte, 16)
		_, _ = rand.Read(a.credID)
	}
	rp := sha256.Sum256([]byte(a.RPID))
	flags := byte(0x41) // UP | AT
	if uv {
		flags |= 0x04
	}
	pub, _ := a.key.PublicKey.Bytes() // 0x04 || X || Y
	x, y := pub[1:33], pub[33:65]
	cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	auth := append(rp[:], flags, 0, 0, 0, 0)
	auth = append(auth, make([]byte, 16)...)
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(a.credID))) // #nosec G115 -- 16-byte test credential id
	auth = append(auth, a.credID...)
	auth = append(auth, cose...)
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": auth})
	body, _ := json.Marshal(map[string]any{"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64(a.clientData("webauthn.create", o.PublicKey.Challenge)), "attestationObject": b64(att)}})
	return body
}

// Assert answers a request (opts is the JSON of the CredentialAssertion).
func (a *Authenticator) Assert(t *testing.T, opts json.RawMessage, uv bool) []byte {
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(opts, &o); err != nil {
		t.Fatal(err)
	}
	a.count++
	rp := sha256.Sum256([]byte(a.RPID))
	flags := byte(0x01)
	if uv {
		flags |= 0x04
	}
	ad := append(rp[:], flags)
	ad = binary.BigEndian.AppendUint32(ad, a.count)
	cd := a.clientData("webauthn.get", o.PublicKey.Challenge)
	cdh := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64(cd), "authenticatorData": b64(ad), "signature": b64(sig)}})
	return body
}
