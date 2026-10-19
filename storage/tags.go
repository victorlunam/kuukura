package storage

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Tags is a normalized tag set: lowercase, deduplicated, sorted, `key:value`.
type Tags []string

const MaxTags = 10

var tagPart = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)

// NormalizeTags validates and canonicalizes tags.
func NormalizeTags(in []string) (Tags, error) {
	out := make(Tags, 0, len(in))
	for _, t := range in {
		t = strings.ToLower(t)
		k, v, ok := strings.Cut(t, ":")
		if !ok || !tagPart.MatchString(k) || !tagPart.MatchString(v) {
			return nil, fmt.Errorf("invalid tag %q", t)
		}
		out = append(out, t)
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > MaxTags {
		return nil, fmt.Errorf("too many tags (max %d)", MaxTags)
	}
	return out, nil
}

// Scan reads a tags column from either dialect: Postgres text[] arrives as
// "{a:b,c:d}", SQLite as the canonical ",a:b,c:d,". Tag characters never need
// array quoting, so a plain split is exact.
func (t *Tags) Scan(src any) error {
	var s string
	switch v := src.(type) {
	case string:
		s = v
	case []byte:
		s = string(v)
	case nil:
		*t = Tags{}
		return nil
	default:
		return fmt.Errorf("storage: cannot scan %T into Tags", src)
	}
	s = strings.Trim(s, "{},")
	*t = Tags{}
	if s != "" {
		*t = strings.Split(s, ",")
	}
	return nil
}

// sqliteTags is the SQLite canonical form: ",a:b,c:d," (empty set is ",").
func sqliteTags(t Tags) string {
	if len(t) == 0 {
		return ","
	}
	return "," + strings.Join(t, ",") + ","
}
