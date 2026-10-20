package masterkey

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/audit"
)

// RevealedAt is when the key with this id was last shown, from the audit log, and whether it ever was. A key
// version is shown once: that keeps it out of scrollback and logs and tells the operator to store it, though
// whoever has host access can still read the key file.
func RevealedAt(ctx context.Context, log *audit.Log, keyID string) (time.Time, bool, error) {
	rows, err := log.Find(ctx, "read", "key")
	if err != nil {
		return time.Time{}, false, err
	}
	for _, r := range rows {
		if r.Metadata["key_id"] == keyID {
			return r.At, true, nil
		}
	}
	return time.Time{}, false, nil
}

// RecordReveal audits that the key with this id was shown by `by`, which is what RevealedAt finds later.
func RecordReveal(ctx context.Context, log *audit.Log, by uuid.UUID, keyID string) error {
	return log.Record(ctx, audit.Entry{Principal: by, Action: "read", TargetType: "key", Metadata: map[string]any{"key_id": keyID}})
}
