package keys

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// ErrWrap is a failed Wrap: KMS refused or could not be reached. It carries the AWS error code (no plaintext is
// involved in the message), so an operator can tell a missing permission from a disabled key or a network fault.
var ErrWrap = errors.New("keys: cannot wrap")

// KMSAPI is the slice of the AWS KMS client we use (a test fake implements it too).
type KMSAPI interface {
	Encrypt(ctx context.Context, in *kms.EncryptInput, opts ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, in *kms.DecryptInput, opts ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// KMS wraps DEKs with an AWS KMS key. The AAD travels as the encryption context.
type KMS struct {
	api KMSAPI
	arn string
}

// NewKMS uses credentials and region from the standard AWS environment.
func NewKMS(ctx context.Context, arn string) (*KMS, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &KMS{api: kms.NewFromConfig(cfg), arn: arn}, nil
}

func NewKMSWithAPI(api KMSAPI, arn string) *KMS { return &KMS{api, arn} }

func (k *KMS) KeyID() string { return "aws-kms:" + k.arn }

func kmsContext(aad []byte) map[string]string {
	return map[string]string{"aad": base64.RawURLEncoding.EncodeToString(aad)}
}

// Wrap always uses the current key.
func (k *KMS) Wrap(ctx context.Context, dek, aad []byte) ([]byte, error) {
	out, err := k.api.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String(k.arn), Plaintext: dek, EncryptionContext: kmsContext(aad)})
	if err != nil {
		var coded interface{ ErrorCode() string }
		if errors.As(err, &coded) {
			return nil, fmt.Errorf("%w: %s", ErrWrap, coded.ErrorCode())
		}
		return nil, ErrWrap
	}
	return out.CiphertextBlob, nil
}

// Unwrap decrypts with the key the DEK was wrapped under (its stored key id), not the current one: after
// VAULT_KMS_KEY_ARN points at a new key, old rows stay readable until rotate-key rewraps them. The key id is
// bound into the wrap AAD, and KMS refuses a ciphertext that does not belong to the key it is asked for.
func (k *KMS) Unwrap(ctx context.Context, keyID string, wrapped, aad []byte) ([]byte, error) {
	arn, ok := strings.CutPrefix(keyID, "aws-kms:")
	if !ok || arn == "" {
		return nil, ErrDecrypt
	}
	out, err := k.api.Decrypt(ctx, &kms.DecryptInput{KeyId: aws.String(arn), CiphertextBlob: wrapped, EncryptionContext: kmsContext(aad)})
	if err != nil {
		return nil, ErrDecrypt
	}
	return out.Plaintext, nil
}
