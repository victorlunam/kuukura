package secrets

import (
	"regexp"
	"strings"

	"github.com/victorlunam/kuukura/internal/access"
	"github.com/victorlunam/kuukura/internal/storage"
)

var nameRE = regexp.MustCompile(`^[A-Z0-9_]{1,128}$`)

// Selector is an optional name plus tags, ANDed.
type Selector struct {
	Name string
	Tags []string
}

type selector struct {
	name string
	tags storage.Tags
}

func (s Selector) parse() (selector, error) {
	var out selector
	if s.Name != "" {
		out.name = strings.ToUpper(s.Name)
		if !nameRE.MatchString(out.name) {
			return out, fail(access.CodeInvalid, "invalid name")
		}
	}
	t, err := storage.NormalizeTags(s.Tags)
	if err != nil {
		return out, fail(access.CodeInvalid, err.Error())
	}
	out.tags = t
	return out, nil
}

// uniqueKeys rejects a secret with two values for one tag key (env:dev env:prod).
func uniqueKeys(t storage.Tags) error {
	seen := map[string]bool{}
	for _, x := range t {
		if k := tagKey(x); seen[k] {
			return fail(access.CodeInvalid, "a tag key can only be used once: "+k)
		} else {
			seen[k] = true
		}
	}
	return nil
}
