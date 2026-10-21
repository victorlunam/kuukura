package main

import (
	"fmt"
	"regexp"
	"strings"
)

type selReq struct {
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags"`
	Not  []string `json:"not_tags,omitempty"`
}

// notMark starts an excluded tag ("~key:value"). The shell leaves it alone: a tilde expands only before a user
// name, and a tag has a colon.
const notMark = "~"

// newSel builds the request from a name and tags where "~key:value" entries are exclusions.
func newSel(name string, tags []string) selReq {
	pos, not := splitNot(tags)
	return selReq{name, nonNilTags(pos), not}
}

// splitNot separates the tags a secret must have from the "~key:value" ones it must not have.
func splitNot(tags []string) (pos, not []string) {
	for _, t := range tags {
		if x, ok := strings.CutPrefix(t, notMark); ok {
			not = append(not, x)
		} else {
			pos = append(pos, t)
		}
	}
	return
}

// tagRE is the server's tag shape: key:value, each part lowercase letters, digits, dot, dash or underscore.
var tagRE = regexp.MustCompile(`^[a-z0-9._-]{1,64}:[a-z0-9._-]{1,64}$`)

// tagPartRE is one part of it, also the shape of an app name.
var tagPartRE = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)

// notATag is the error for the n-th argument (1-based) that is not a tag. It never repeats the argument: a
// secret value typed by mistake would otherwise land in the terminal, its scrollback and logs.
func notATag(n int) error { return fmt.Errorf("argument %d is not a tag (key:value)", n) }

// withApp adds app:<app> when the folder is linked and no app: tag was given (an explicit one always wins), and says
// so on stderr, so the scope of the command is never a surprise.
func (a *app) withApp(pr profile, tags []string) []string {
	if pr.app == "" || hasKey(tags, "app") {
		return tags
	}
	a.say("app: %s (linked folder)", pr.app)
	return append(tags, "app:"+pr.app)
}

// selectorFrom turns positionals into a name (first, no colon) and tags (key:value). Everything with a colon must
// be a valid tag: a value such as postgres://user:pw@host/db is rejected here, before it can be sent anywhere.
// A tag with a leading "~" is an exclusion and stays in tags with its mark (see splitNot). Every tag, excluded or
// not, is key:value: "~role" alone is an error, not a name.
func selectorFrom(pos []string) (name string, tags []string, err error) {
	for i, t := range pos {
		switch {
		case strings.HasPrefix(t, notMark), strings.Contains(t, ":"):
			t = strings.ToLower(t)
			if !tagRE.MatchString(strings.TrimPrefix(t, notMark)) {
				return "", nil, notATag(i + 1)
			}
			tags = append(tags, t)
		case i == 0:
			name = strings.ToUpper(t)
		default:
			return "", nil, notATag(i + 1)
		}
	}
	return name, tags, nil
}
