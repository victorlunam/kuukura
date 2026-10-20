package main

import (
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
)

// version is set at release time: -ldflags "-X main.version=2026.10.0".
var version = "dev"

const helpText = `ku-server serve | healthcheck | version
ku-server key   init | rotate | show
ku-server user  list | invite <email> [--admin] | disable <email|machine> | enable <email|machine> | reset-factors <email>
ku-server audit verify
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type subcommands map[string]func(args []string) error

func run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Print(helpText)
		return nil
	}
	switch args[0] {
	case "version", "--version":
		fmt.Println(version)
		return nil
	case "healthcheck":
		return runHealthcheck()
	case "serve":
		return runServe(args[1:])
	case "key":
		return subcommands{"init": runKeyInit, "rotate": runKeyRotate, "show": runKeyShow}.run("key", args[1:])
	case "user":
		return subcommands{"list": runUserList, "invite": runUserInvite, "disable": runUserDisable,
			"enable": runUserEnable, "reset-factors": runUserResetFactors}.run("user", args[1:])
	case "audit":
		return subcommands{"verify": runAuditVerify}.run("audit", args[1:])
	}
	return fmt.Errorf("unknown command %q; run `ku-server help`", args[0])
}

func (s subcommands) run(group string, args []string) error {
	if len(args) > 0 {
		if fn, ok := s[args[0]]; ok {
			return fn(args[1:])
		}
	}
	return fmt.Errorf("usage: ku-server %s <%s>", group, strings.Join(slices.Sorted(maps.Keys(s)), "|"))
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
