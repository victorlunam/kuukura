package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
)

// version is set at release time: -ldflags "-X main.version=YEAR.MONTH.N".
var version = "dev"

// helpText is the help: one line per command, "noun verb arguments", then what it does (same shape as `ku help`).
const helpText = `Usage: ku-server <command> [options]

  serve                          start the server
  healthcheck                    check the running server (for the container)
  version                        print the version
  key init [--key-file <path>]   write a new master key file
  key rotate [--rewrap-only]     add a key version and rewrap every secret
  key show                       show the master key once, to back it up
  user list                      list people and machines
  user invite <email> [--admin]  print a sign-up link
  user disable <email|name>      block a person or machine
  user enable <email|name>       lift the block
  user reset-factors <email>     remove passkeys and apps, print a link
  audit verify                   check the audit log chain
`

// Exit codes: 1 when the command ran and failed, 2 when the arguments were wrong (ku uses the same).
const (
	exitFail  = 1
	exitUsage = 2
)

// usageError is a command that got wrong arguments. Its text is the usage line; what was typed is never echoed,
// because a secret passed as an argument by mistake must not come back in the terminal or the shell history.
type usageError string

func (e usageError) Error() string { return "Usage: " + string(e) }

func main() { os.Exit(report(run(os.Args[1:]))) }

// report prints an error and returns the exit code: a usage line for wrong arguments, otherwise
// "ku-server: <Sentence.>" (the same sentence rule as `ku`: a capital and a final period).
func report(err error) int {
	var u usageError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &u):
		fmt.Fprintln(os.Stderr, u)
		return exitUsage
	case errors.Is(err, errUnknown):
		fmt.Fprint(os.Stderr, helpText)
		return exitUsage
	}
	for line := range strings.SplitSeq(err.Error(), "\n") { // a bad configuration reports every problem, one per line
		fmt.Fprintf(os.Stderr, "ku-server: %s\n", sentence(line))
	}
	return exitFail
}

// sentence makes s read as a sentence: a capital first letter and a final period (unless it ends a list with ":").
func sentence(s string) string {
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

type subcommands map[string]func(args []string) error

// errUnknown is no command, or one that does not exist: the help goes to stderr and it exits 2, like `ku` does.
var errUnknown = errors.New("unknown command")

func run(args []string) error {
	if len(args) == 0 {
		return errUnknown
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
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
		return subcommands{"init": runKeyInit, "rotate": runKeyRotate, "show": runKeyShow}.run("key", "init|rotate|show", args[1:])
	case "user":
		return subcommands{"list": runUserList, "invite": runUserInvite, "disable": runUserDisable,
			"enable": runUserEnable, "reset-factors": runUserResetFactors}.run("user", "list|invite|disable|enable|reset-factors", args[1:])
	case "audit":
		return subcommands{"verify": runAuditVerify}.run("audit", "verify", args[1:])
	}
	return errUnknown
}

// run dispatches `ku-server <group> <verb>`; verbs is how the usage line lists them.
func (s subcommands) run(group, verbs string, args []string) error {
	if len(args) > 0 {
		if fn, ok := s[args[0]]; ok {
			return fn(args[1:])
		}
	}
	return usageError("ku-server " + group + " " + verbs)
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
