package keys

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/google/uuid"
)

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
