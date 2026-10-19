package keys

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/google/uuid"
)

var ctx = context.Background()

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

// fakeKMS binds the encryption context like the real service.
type fakeKMS struct{}

func (fakeKMS) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	return &kms.EncryptOutput{CiphertextBlob: append([]byte(in.EncryptionContext["aad"]+"|"), in.Plaintext...)}, nil
}
func (fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	ctxPart, pt, _ := bytes.Cut(in.CiphertextBlob, []byte("|"))
	if string(ctxPart) != in.EncryptionContext["aad"] {
		return nil, errors.New("InvalidCiphertextException")
	}
	return &kms.DecryptOutput{Plaintext: pt}, nil
}

func providers(t *testing.T) map[string]KeyProvider {
	return map[string]KeyProvider{
		"manual": manual(t, 1),
		"kms":    NewKMSWithAPI(fakeKMS{}, "arn:aws:kms:eu-west-1:000000000000:key/fake"),
	}
}

const fakeValue = "sk_test_FAKE_EXAMPLE"

func TestRoundTrip(t *testing.T) {
	for name, kp := range providers(t) {
		t.Run(name, func(t *testing.T) {
			id := uuid.New()
			p, err := Seal(ctx, kp, id, 1, []byte(fakeValue))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(p.Ciphertext, []byte(fakeValue)) || len(p.Nonce) != 12 || p.FormatVersion != 1 {
				t.Fatal("bad payload")
			}
			got, err := Open(ctx, kp, id, 1, p)
			if err != nil || string(got) != fakeValue {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

func TestTamperAndMove(t *testing.T) {
	for name, kp := range providers(t) {
		t.Run(name, func(t *testing.T) {
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

func TestDomainSeparation(t *testing.T) {
	m := manual(t, 1)
	id := uuid.New()
	dek := bytes.Repeat([]byte{7}, 32)
	wrapped, _ := m.Wrap(ctx, dek, AAD(PurposePayload, 1, id, 1, m.KeyID()))
	if _, err := m.Unwrap(ctx, m.KeyID(), wrapped, AAD(PurposeWrap, 1, id, 1, m.KeyID())); err == nil {
		t.Fatal("payload-purpose wrap accepted as wrap-purpose")
	}
	// a payload sealed with the wrap AAD must not open as a payload
	p, _ := Seal(ctx, m, id, 1, []byte(fakeValue))
	gcm, _ := newGCM(bytes.Repeat([]byte{9}, 32))
	bad := gcm.Seal(nil, p.Nonce, []byte(fakeValue), wrapAAD(id, 1, p.KeyID))
	if _, err := gcm.Open(nil, p.Nonce, bad, payloadAAD(id, 1)); err == nil {
		t.Fatal("wrap AAD accepted as payload AAD")
	}
}

func TestRotationKeepsCiphertext(t *testing.T) {
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

func TestExportedKeyUnlocksSecret(t *testing.T) {
	keyFile, _ := GenerateMasterKey(1)
	m, _ := ParseMasterKeys(keyFile)
	id := uuid.New()
	p, _ := Seal(ctx, m, id, 1, []byte(fakeValue))

	var out bytes.Buffer
	if err := ExportMasterKey(&out, keyFile, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), keyFile) {
		t.Fatal("export is not encrypted")
	}
	if _, err := ImportMasterKey(bytes.NewReader(out.Bytes()), "wrong passphrase!!"); err == nil {
		t.Fatal("wrong passphrase must fail")
	}
	restored, err := ImportMasterKey(bytes.NewReader(out.Bytes()), "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	m2, err := ParseMasterKeys(restored)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(ctx, m2, id, 1, p); err != nil || string(got) != fakeValue {
		t.Fatal("restored key must unlock the secret")
	}
	if err := ExportMasterKey(&bytes.Buffer{}, keyFile, "short"); err == nil {
		t.Fatal("short passphrase must be rejected")
	}
}

func TestSealedLeaksNothing(t *testing.T) {
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

func FuzzParseAAD(f *testing.F) {
	f.Add(AAD(PurposePayload, 1, uuid.New(), 1, "manual:v1"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParseAAD(b)
		if err != nil {
			return
		}
		if !bytes.Equal(AAD(p.Purpose, p.Format, p.SecretID, p.Number, p.KeyID), b) {
			t.Fatal("parse/build round trip mismatch")
		}
	})
}

func FuzzOpen(f *testing.F) {
	m, _ := ParseMasterKeys([]byte("1:" + base64.StdEncoding.EncodeToString(make([]byte, 32))))
	id := uuid.New()
	p, _ := Seal(ctx, m, id, 1, []byte(fakeValue))
	f.Add(p.Ciphertext, p.Nonce, p.WrappedKey, p.KeyID)
	f.Fuzz(func(t *testing.T, ct, nonce, wrapped []byte, keyID string) {
		got, err := Open(ctx, m, id, 1, Payload{ct, nonce, wrapped, keyID, 1})
		if err == nil && !bytes.Equal(ct, p.Ciphertext) {
			t.Fatalf("forged payload opened: %q", got)
		}
	})
}
