package keys

import (
	"encoding/binary"
	"errors"

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
	b = binary.BigEndian.AppendUint16(b, uint16(len(keyID)))
	return append(b, keyID...)
}

// ParsedAAD is the decoded form of AAD bytes.
type ParsedAAD struct {
	Purpose, Format byte
	SecretID        uuid.UUID
	Number          uint32
	KeyID           string
}

var errAAD = errors.New("keys: malformed aad")

func ParseAAD(b []byte) (ParsedAAD, error) {
	var p ParsedAAD
	if len(b) < 24 {
		return p, errAAD
	}
	p.Purpose, p.Format = b[0], b[1]
	copy(p.SecretID[:], b[2:18])
	p.Number = binary.BigEndian.Uint32(b[18:22])
	n := int(binary.BigEndian.Uint16(b[22:24]))
	if len(b) != 24+n {
		return p, errAAD
	}
	p.KeyID = string(b[24:])
	return p, nil
}
