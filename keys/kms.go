package keys

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

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

func (k *KMS) Wrap(ctx context.Context, dek, aad []byte) ([]byte, error) {
	out, err := k.api.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String(k.arn), Plaintext: dek, EncryptionContext: kmsContext(aad)})
	if err != nil {
		return nil, ErrDecrypt
	}
	return out.CiphertextBlob, nil
}

func (k *KMS) Unwrap(ctx context.Context, keyID string, wrapped, aad []byte) ([]byte, error) {
	if !strings.HasPrefix(keyID, "aws-kms:") || keyID != k.KeyID() {
		return nil, ErrDecrypt
	}
	out, err := k.api.Decrypt(ctx, &kms.DecryptInput{KeyId: aws.String(k.arn), CiphertextBlob: wrapped, EncryptionContext: kmsContext(aad)})
	if err != nil {
		return nil, ErrDecrypt
	}
	return out.Plaintext, nil
}
