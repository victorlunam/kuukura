package keys

import (
	"errors"
	"io"

	"filippo.io/age"
)

const minPassphrase = 12

// ExportMasterKey writes the key file body as an age file protected by a
// passphrase (scrypt recipient), for offline storage. Restoring is `age -d`.
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
