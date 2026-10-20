package keys

import "fmt"

// MismatchError is the start-up refusal when the configured key cannot open stored data. The key id it names is
// the one stored with the data, not key material.
func MismatchError(keyID string) error {
	return fmt.Errorf("the master key does not match the data (key %s cannot open it)", keyID)
}
