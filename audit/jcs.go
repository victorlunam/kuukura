package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"unicode/utf16"
)

// jcs encodes v as RFC 8785 canonical JSON. Supported: nil, bool, string,
// integers (int, int64, json.Number holding an integer), []any, map[string]any.
// Floats are rejected; audit metadata never needs them.
func jcs(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := jcsWrite(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func jcsWrite(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		jcsString(b, x)
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case json.Number:
		i, err := strconv.ParseInt(x.String(), 10, 64)
		if err != nil {
			return fmt.Errorf("audit: non-integer number %q in canonical json", x)
		}
		b.WriteString(strconv.FormatInt(i, 10))
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := jcsWrite(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, func(a, c string) int { return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(c))) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			jcsString(b, k)
			b.WriteByte(':')
			if err := jcsWrite(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("audit: unsupported type %T in canonical json", v)
	}
	return nil
}

func jcsString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}
