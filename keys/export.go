package keys

import (
	"bytes"
	"errors"
	"io"

	"filippo.io/age"
)

const minPassphrase = 12

// ExportMasterKey writes the key file body as an age file protected by a
// passphrase (scrypt recipient), for offline storage.
func ExportMasterKey(w io.Writer, keyFile []byte, passphrase string) error {
	if len(passphrase) < minPassphrase {
		return errors.New("keys: passphrase too short")
	}
	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return err
	}
	enc, err := age.Encrypt(w, r)
	if err != nil {
		return err
	}
	if _, err := enc.Write(keyFile); err != nil {
		return err
	}
	return enc.Close()
}

// ImportMasterKey decrypts an exported file; a wrong passphrase gives a generic error.
func ImportMasterKey(r io.Reader, passphrase string) ([]byte, error) {
	id, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	dec, err := age.Decrypt(r, id)
	if err != nil {
		return nil, ErrDecrypt
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, dec); err != nil {
		return nil, ErrDecrypt
	}
	return buf.Bytes(), nil
}
