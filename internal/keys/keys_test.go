package keys

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/google/uuid"
)

func manual(t *testing.T, versions ...int) *Manual {
	t.Helper()
	var all []byte
	for _, v := range versions {
		b, err := GenerateMasterKey(v)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, b...)
	}
	m, err := ParseMasterKeys(all)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// fakeKMS binds the key and the encryption context like the real service: a ciphertext opens only under the
// key it was made with and the context it was made with.
type fakeKMS struct {
	encryptErr error
}

func (f fakeKMS) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if f.encryptErr != nil {
		return nil, f.encryptErr
	}
	blob := *in.KeyId + "|" + in.EncryptionContext["aad"] + "|"
	return &kms.EncryptOutput{CiphertextBlob: append([]byte(blob), in.Plaintext...)}, nil
}

func (fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	parts := bytes.SplitN(in.CiphertextBlob, []byte("|"), 3)
	if len(parts) != 3 || string(parts[0]) != *in.KeyId || string(parts[1]) != in.EncryptionContext["aad"] {
		return nil, errors.New("InvalidCiphertextException")
	}
	return &kms.DecryptOutput{Plaintext: slices.Clone(parts[2])}, nil // a fresh slice, as the real client returns
}

const (
	arnOld = "arn:aws:kms:eu-west-1:000000000000:key/fake-old"
	arnNew = "arn:aws:kms:eu-west-1:000000000000:key/fake-new"
)

func providers(t *testing.T) map[string]KeyProvider {
	return map[string]KeyProvider{
		"manual": manual(t, 1),
		"kms":    NewKMSWithAPI(fakeKMS{}, arnOld),
	}
}

const fakeValue = "sk_test_FAKE_EXAMPLE"

func TestRoundTrip(t *testing.T) {
	for name, kp := range providers(t) {
		t.Run(name, func(t *testing.T) {
			id := uuid.New()
			p, err := Seal(t.Context(), kp, id, 1, []byte(fakeValue))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(p.Ciphertext, []byte(fakeValue)) || len(p.Nonce) != 12 || p.FormatVersion != 1 {
				t.Fatal("bad payload")
			}
			got, err := Open(t.Context(), kp, id, 1, p)
			if err != nil || string(got) != fakeValue {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

func TestTamperAndMove(t *testing.T) {
	for name, kp := range providers(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			id := uuid.New()
			p, _ := Seal(ctx, kp, id, 1, []byte(fakeValue))
			flip := func(b []byte) []byte { c := slices.Clone(b); c[0] ^= 1; return c }
			cases := map[string]func() error{
				"ciphertext":    func() error { q := p; q.Ciphertext = flip(p.Ciphertext); _, err := Open(ctx, kp, id, 1, q); return err },
				"nonce":         func() error { q := p; q.Nonce = flip(p.Nonce); _, err := Open(ctx, kp, id, 1, q); return err },
				"wrapped":       func() error { q := p; q.WrappedKey = flip(p.WrappedKey); _, err := Open(ctx, kp, id, 1, q); return err },
				"key_id":        func() error { q := p; q.KeyID += "x"; _, err := Open(ctx, kp, id, 1, q); return err },
				"format":        func() error { q := p; q.FormatVersion = 2; _, err := Open(ctx, kp, id, 1, q); return err },
				"other secret":  func() error { _, err := Open(ctx, kp, uuid.New(), 1, p); return err },
				"other version": func() error { _, err := Open(ctx, kp, id, 2, p); return err },
			}
			for n, f := range cases {
				if err := f(); !errors.Is(err, ErrDecrypt) {
					t.Errorf("%s: got %v, want ErrDecrypt", n, err)
				}
			}
		})
	}
}

func TestAADLayout(t *testing.T) {
	id := uuid.MustParse("00112233-4455-6677-8899-aabbccddeeff")
	got := AAD(PurposeWrap, 1, id, 0x01020304, "manual:v2")
	want := append([]byte{0x02, 0x01}, id[:]...)
	want = append(want, 1, 2, 3, 4, 0, 9)
	want = append(want, "manual:v2"...)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
	if binary.BigEndian.Uint16(got[22:24]) != 9 {
		t.Fatal("length prefix")
	}
}

// A DEK wrapped for the payload purpose must not open a payload: Open unwraps with the wrap purpose.
func TestDomainSeparation(t *testing.T) {
	ctx := t.Context()
	m := manual(t, 1)
	id := uuid.New()
	dek := bytes.Repeat([]byte{7}, 32)
	if _, err := m.Unwrap(ctx, m.KeyID(), mustWrap(t, m, dek, AAD(PurposePayload, 1, id, 1, m.KeyID())), AAD(PurposeWrap, 1, id, 1, m.KeyID())); err == nil {
		t.Fatal("payload-purpose wrap accepted as wrap-purpose")
	}

	gcm, err := newGCM(dek)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{3}, gcm.NonceSize())
	forge := func(wrapAADBytes []byte) Payload {
		return Payload{
			Ciphertext: gcm.Seal(nil, nonce, []byte(fakeValue), payloadAAD(id, 1)), Nonce: nonce,
			WrappedKey: mustWrap(t, m, dek, wrapAADBytes), KeyID: m.KeyID(), FormatVersion: FormatV1,
		}
	}
	if got, err := Open(ctx, m, id, 1, forge(wrapAAD(id, 1, m.KeyID()))); err != nil || string(got) != fakeValue {
		t.Fatalf("control: a correctly wrapped payload must open: %v", err)
	}
	if _, err := Open(ctx, m, id, 1, forge(AAD(PurposePayload, FormatV1, id, 1, m.KeyID()))); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("a DEK wrapped for the payload purpose must not open the payload: %v", err)
	}
}

func mustWrap(t *testing.T, kp KeyProvider, dek, aad []byte) []byte {
	t.Helper()
	w, err := kp.Wrap(t.Context(), dek, aad)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestRotationKeepsCiphertext(t *testing.T) {
	ctx := t.Context()
	v1 := manual(t, 1)
	id := uuid.New()
	p, _ := Seal(ctx, v1, id, 3, []byte(fakeValue))
	// v2 ring = the v1 key plus a new one
	k2, _ := GenerateMasterKey(2)
	body := fmt.Appendf(nil, "1:%s\n", base64.StdEncoding.EncodeToString(v1.ring[1]))
	ring, err := ParseMasterKeys(append(body, k2...))
	if err != nil || ring.KeyID() != "manual:v2" {
		t.Fatalf("ring: %v %v", err, ring)
	}
	if got, err := Open(ctx, ring, id, 3, p); err != nil || string(got) != fakeValue {
		t.Fatal("old data must stay readable after rotation")
	}
	q, err := Rewrap(ctx, ring, id, 3, p)
	if err != nil || q.KeyID != "manual:v2" || !bytes.Equal(q.Ciphertext, p.Ciphertext) || !bytes.Equal(q.Nonce, p.Nonce) {
		t.Fatal("rewrap must change only the wrapped key")
	}
	if got, err := Open(ctx, ring, id, 3, q); err != nil || string(got) != fakeValue {
		t.Fatal("rewrapped data unreadable")
	}
	if _, err := Open(ctx, v1, id, 3, q); err == nil {
		t.Fatal("v1-only ring must not open v2-wrapped data")
	}
}

// The runbook points VAULT_KMS_KEY_ARN at a new key and runs rotate-key: data wrapped under the old ARN must stay
// readable meanwhile, and the rewrap must move it to the new one.
func TestKMSKeyRotation(t *testing.T) {
	ctx := t.Context()
	oldKey, newKey := NewKMSWithAPI(fakeKMS{}, arnOld), NewKMSWithAPI(fakeKMS{}, arnNew)
	id := uuid.New()
	p, err := Seal(ctx, oldKey, id, 2, []byte(fakeValue))
	if err != nil || p.KeyID != "aws-kms:"+arnOld {
		t.Fatalf("%v %q", err, p.KeyID)
	}
	if got, err := Open(ctx, newKey, id, 2, p); err != nil || string(got) != fakeValue {
		t.Fatalf("data under the old ARN must stay readable after the switch: %v", err)
	}
	q, err := Rewrap(ctx, newKey, id, 2, p)
	if err != nil || q.KeyID != "aws-kms:"+arnNew || !bytes.Equal(q.Ciphertext, p.Ciphertext) {
		t.Fatalf("rewrap: %v %q", err, q.KeyID)
	}
	if got, err := Open(ctx, newKey, id, 2, q); err != nil || string(got) != fakeValue {
		t.Fatalf("rewrapped data unreadable: %v", err)
	}
}

func TestKMSKeyIDMismatch(t *testing.T) {
	ctx := t.Context()
	kp := NewKMSWithAPI(fakeKMS{}, arnNew)
	id := uuid.New()
	kmsPayload, _ := Seal(ctx, NewKMSWithAPI(fakeKMS{}, arnOld), id, 1, []byte(fakeValue))
	manualPayload, _ := Seal(ctx, manual(t, 1), id, 1, []byte(fakeValue))

	if _, err := Open(ctx, kp, id, 1, manualPayload); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("a manual payload under a KMS provider: %v", err)
	}
	if _, err := Open(ctx, manual(t, 1), id, 1, kmsPayload); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("a KMS payload under a manual provider: %v", err)
	}
	// a key id naming another key than the one that wrapped the DEK: KMS refuses it
	q := kmsPayload
	q.KeyID = "aws-kms:" + arnNew
	if _, err := Open(ctx, kp, id, 1, q); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong ARN: %v", err)
	}
	q.KeyID = "aws-kms:"
	if _, err := Open(ctx, kp, id, 1, q); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("empty ARN: %v", err)
	}
}

type apiErr struct{}

func (apiErr) Error() string     { return "api error AccessDeniedException: User is not authorized" }
func (apiErr) ErrorCode() string { return "AccessDeniedException" }

func TestKMSWrapErrorKeepsTheCode(t *testing.T) {
	ctx := t.Context()
	_, err := Seal(ctx, NewKMSWithAPI(fakeKMS{encryptErr: apiErr{}}, arnOld), uuid.New(), 1, []byte(fakeValue))
	if !errors.Is(err, ErrWrap) || errors.Is(err, ErrDecrypt) || !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Fatalf("want ErrWrap with the AWS code, got %v", err)
	}
	if strings.Contains(err.Error(), fakeValue) {
		t.Fatal("no value in the error")
	}
	_, err = Seal(ctx, NewKMSWithAPI(fakeKMS{encryptErr: errors.New("dial tcp: i/o timeout")}, arnOld), uuid.New(), 1, []byte(fakeValue))
	if !errors.Is(err, ErrWrap) {
		t.Fatalf("an uncoded error is still a wrap error: %v", err)
	}
}

func TestParseMasterKeysRejects(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	other := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	cases := map[string]string{
		"version 0":          "0:" + good,
		"negative version":   "-1:" + good,
		"not a version":      "x:" + good,
		"short key":          "1:" + base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"not base64":         "1:!!!",
		"duplicate version":  "1:" + good + "\n1:" + other,
		"empty":              "\n  \n",
		"bad second line":    "1:" + good + "\n2:short",
		"duplicate, spaced":  "2:" + good + "\n\n 2:" + other + "\n",
		"version no key":     "3:",
		"version only colon": ":",
	}
	for name, body := range cases {
		m, err := ParseMasterKeys([]byte(body))
		if err == nil {
			t.Errorf("%s: accepted (%v)", name, m)
			continue
		}
		if strings.Contains(err.Error(), good) || strings.Contains(err.Error(), other) {
			t.Errorf("%s: the error echoes key material: %v", name, err)
		}
	}
	m, err := ParseMasterKeys([]byte("1:" + good + "\n\n3:" + other + "\n"))
	if err != nil || m.Version() != 3 {
		t.Fatalf("a valid ring with a gap must load: %v", err)
	}
}

// probe records the key slices the envelope code hands to and gets from the provider.
type probe struct {
	*Manual
	wrapped, unwrapped [][]byte
}

func (p *probe) Wrap(ctx context.Context, dek, aad []byte) ([]byte, error) {
	p.wrapped = append(p.wrapped, dek)
	return p.Manual.Wrap(ctx, dek, aad)
}

func (p *probe) Unwrap(ctx context.Context, keyID string, wrapped, aad []byte) ([]byte, error) {
	dek, err := p.Manual.Unwrap(ctx, keyID, wrapped, aad)
	p.unwrapped = append(p.unwrapped, dek)
	return dek, err
}

func TestDEKIsClearedAfterUse(t *testing.T) {
	ctx := t.Context()
	pr := &probe{Manual: manual(t, 1)}
	id := uuid.New()
	p, err := Seal(ctx, pr, id, 1, []byte(fakeValue))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, pr, id, 1, p); err != nil {
		t.Fatal(err)
	}
	if _, err := Rewrap(ctx, pr, id, 1, p); err != nil {
		t.Fatal(err)
	}
	if len(pr.wrapped) != 2 || len(pr.unwrapped) != 2 {
		t.Fatalf("probe saw %d wraps, %d unwraps", len(pr.wrapped), len(pr.unwrapped))
	}
	for _, d := range append(pr.wrapped, pr.unwrapped...) {
		if !bytes.Equal(d, make([]byte, 32)) {
			t.Fatal("a DEK stayed in memory after use")
		}
	}
}

// A bare key (what a platform generates for an env var) is version 1 and unlocks what the same key in a key file
// unlocks.
func TestParseBareMasterKey(t *testing.T) {
	ctx := t.Context()
	raw := bytes.Repeat([]byte{7}, 32)
	b64 := base64.StdEncoding.EncodeToString(raw)
	ringed, err := ParseMasterKeys([]byte("1:" + b64))
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	p, _ := Seal(ctx, ringed, id, 1, []byte(fakeValue))
	for name, body := range map[string]string{"base64": b64 + "\n", "hex": " " + hex.EncodeToString(raw) + " "} {
		m, err := ParseMasterKeys([]byte(body))
		if err != nil || m.Version() != 1 || m.KeyID() != "manual:v1" {
			t.Fatalf("%s: %v", name, err)
		}
		if got, err := Open(ctx, m, id, 1, p); err != nil || string(got) != fakeValue {
			t.Fatalf("%s: a bare key must open what version 1 sealed", name)
		}
	}
	for name, body := range map[string]string{
		"hex too short":    strings.Repeat("ab", 31),
		"hex not hex":      strings.Repeat("zz", 32),
		"base64 16 bytes":  base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"base64 url form":  strings.NewReplacer("+", "-", "/", "_").Replace(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32))),
		"two bare lines":   b64 + "\n" + b64,
		"bare then ringed": b64 + "\n2:" + b64,
	} {
		if _, err := ParseMasterKeys([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), body) {
			t.Errorf("%s: the error echoes the input", name)
		}
	}
}

func TestRingRoundTrips(t *testing.T) {
	m := manual(t, 3, 1)
	again, err := ParseMasterKeys(m.Ring())
	if err != nil || again.Version() != 3 || !bytes.Equal(again.Ring(), m.Ring()) {
		t.Fatalf("the ring text must parse back to the same ring: %v", err)
	}
	if !strings.HasPrefix(string(m.Ring()), "1:") {
		t.Fatal("oldest version first")
	}
}

func TestSealedLeaksNothing(t *testing.T) {
	ctx := t.Context()
	m := manual(t, 1)
	id := uuid.New()
	p, _ := Seal(ctx, m, id, 1, []byte(fakeValue))
	_, err := Open(ctx, Sealed{}, id, 1, p)
	if !errors.Is(err, ErrSealed) || err.Error() != "keys: sealed" {
		t.Fatalf("got %v", err)
	}
	if _, err := Seal(ctx, Sealed{}, id, 1, []byte(fakeValue)); !errors.Is(err, ErrSealed) {
		t.Fatal("sealed must not encrypt")
	}
}

func FuzzOpen(f *testing.F) {
	m, _ := ParseMasterKeys([]byte("1:" + base64.StdEncoding.EncodeToString(make([]byte, 32))))
	id := uuid.New()
	p, _ := Seal(context.Background(), m, id, 1, []byte(fakeValue))
	f.Add(p.Ciphertext, p.Nonce, p.WrappedKey, p.KeyID)
	f.Fuzz(func(t *testing.T, ct, nonce, wrapped []byte, keyID string) {
		got, err := Open(t.Context(), m, id, 1, Payload{ct, nonce, wrapped, keyID, 1})
		if err == nil && !bytes.Equal(ct, p.Ciphertext) {
			t.Fatalf("forged payload opened: %q", got)
		}
	})
}
