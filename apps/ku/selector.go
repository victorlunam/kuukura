package main

import (
	"fmt"
	"regexp"
	"strings"
)

type selReq struct {
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags"`
}

// tagRE is the server's tag shape: key:value, each part lowercase letters, digits, dot, dash or underscore.
var tagRE = regexp.MustCompile(`^[a-z0-9._-]{1,64}:[a-z0-9._-]{1,64}$`)

// tagPartRE is one part of it, also the shape of an app name.
var tagPartRE = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)

// notATag is the error for the n-th argument (1-based) that is not a tag. It never repeats the argument: a
// secret value typed by mistake would otherwise land in the terminal, its scrollback and logs.
func notATag(n int) error { return fmt.Errorf("argument %d is not a tag (key:value)", n) }

// selectorFrom turns positionals into a name (first, no colon) and tags (key:value). Everything with a colon must
// be a valid tag: a value such as postgres://user:pw@host/db is rejected here, before it can be sent anywhere.
func selectorFrom(pos []string) (name string, tags []string, err error) {
	for i, t := range pos {
		switch {
		case strings.Contains(t, ":"):
			t = strings.ToLower(t)
			if !tagRE.MatchString(t) {
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
