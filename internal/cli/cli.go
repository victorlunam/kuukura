// Package cli holds the few conventions ku and ku-server share: exit codes, the usage error and how a message
// reads as a sentence. Everything else (argument parsing, output, config) differs between them on purpose.
package cli

import (
	"strings"
	"unicode"
)

// Exit codes: 1 when the command ran and failed, 2 when the arguments were wrong.
const (
	ExitFail  = 1
	ExitUsage = 2
)

// UsageError is a command that got wrong arguments. Its text is the usage line; what was typed is never echoed,
// because a secret passed as an argument by mistake must not come back in the terminal or the shell history.
type UsageError string

func (e UsageError) Error() string { return "Usage: " + string(e) }

// Sentence makes s read as a sentence: a capital first letter and a final period (unless it ends a list with ":").
func Sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if r := []rune(s); unicode.IsLower(r[0]) {
		s = string(unicode.ToUpper(r[0])) + string(r[1:])
	}
	if !strings.ContainsAny(s[len(s)-1:], ".!?:") {
		s += "."
	}
	return s
}
