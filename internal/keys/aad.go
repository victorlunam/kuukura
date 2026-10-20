package keys

import (
	"encoding/binary"

	"github.com/google/uuid"
)

const (
	PurposePayload byte = 0x01
	PurposeWrap    byte = 0x02

	FormatV1 byte = 1
)

// AAD builds the additional authenticated data:
// purpose u8 || format_version u8 || secret_id (16) || number u32 BE || len(key_id) u16 BE || key_id.
func AAD(purpose, format byte, secretID uuid.UUID, number uint32, keyID string) []byte {
	b := make([]byte, 0, 24+len(keyID))
	b = append(b, purpose, format)
	b = append(b, secretID[:]...)
	b = binary.BigEndian.AppendUint32(b, number)
	b = binary.BigEndian.AppendUint16(b, uint16(len(keyID))) // #nosec G115 -- key ids are short (provider-prefixed ARN or manual:vN)
	return append(b, keyID...)
}
