package main

import (
	"flag"
	"io"

	"github.com/victorlunam/kuukura/internal/cli"
)

type subcommands map[string]func(args []string) error

// run dispatches `ku-server <group> <verb>`; verbs is how the usage line lists them.
func (s subcommands) run(group, verbs string, args []string) error {
	if len(args) > 0 {
		if fn, ok := s[args[0]]; ok {
			return fn(args[1:])
		}
	}
	return cli.UsageError("ku-server " + group + " " + verbs)
}

// parseArgs splits args into positional arguments and the flags declared on fs, accepting flags before, between and
// after the positionals (`user invite dev@example.com --admin`). An undeclared flag is an error.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) > 0 {
			pos, args = append(pos, args[0]), args[1:]
		}
	}
	return pos, nil
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// positional parses args into exactly n positional arguments plus the flags declared on fs.
func positional(fs *flag.FlagSet, usage string, args []string, n int) ([]string, error) {
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) != n { // the flag package's error would name what was typed
		return nil, cli.UsageError("ku-server " + usage)
	}
	return pos, nil
}

func noArgs(usage string, args []string) error {
	if len(args) != 0 {
		return cli.UsageError("ku-server " + usage)
	}
	return nil
}
