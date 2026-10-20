package main

import (
	"errors"
	"slices"
	"strings"
)

type parsed struct {
	pos   []string
	flags map[string]string
}

// parseArgs separates positionals from --flags. valued are the flags that take a value, bools the ones that do not;
// any other --flag is an error, so a typo such as --profle never runs against the default profile. Tokens like
// +env:qa and -env:prod are positional (tag changes).
func parseArgs(args []string, valued []string, bools ...string) (parsed, error) {
	p := parsed{flags: map[string]string{}}
	for i := 0; i < len(args); i++ {
		t := args[i]
		if !strings.HasPrefix(t, "--") || t == "--" {
			p.pos = append(p.pos, t)
			continue
		}
		name, val, hasVal := strings.Cut(strings.TrimPrefix(t, "--"), "=")
		switch {
		case slices.Contains(valued, name) && hasVal:
			p.flags[name] = val
		case slices.Contains(valued, name) && i+1 < len(args):
			i++
			p.flags[name] = args[i]
		case slices.Contains(bools, name) && !hasVal:
			p.flags[name] = "true"
		default: // an unknown flag, or a valued one without its value
			return p, errBadFlag
		}
	}
	return p, nil
}

// errBadFlag does not name the flag: the callers answer with the usage line, which lists the valid ones.
var errBadFlag = errors.New("unknown flag or missing value")

// parse is parseArgs for a command: on a bad flag it prints the command's usage line and reports false.
func (a *app) parse(usageLine string, args []string, valued []string, bools ...string) (parsed, bool) {
	p, err := parseArgs(args, valued, bools...)
	if err != nil {
		a.usageFail(usageLine)
		return p, false
	}
	return p, true
}

func (p parsed) has(name string) bool { _, ok := p.flags[name]; return ok }
