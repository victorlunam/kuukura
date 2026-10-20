// Command ku (binary `kuukura`, alias `ku`) is the CLI. Decryption happens on the server;
// the CLI is a secure channel. Values are never accepted as arguments.
package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/victorlunam/kuukura/internal/cli"
)

// version is set at release time: -ldflags "-X main.version=YEAR.MONTH.N".
var version = "dev"

// app holds everything a command touches, so tests can swap it.
type app struct {
	in         io.Reader
	out, err   io.Writer
	getenv     func(string) string
	store      tokenStore
	http       *http.Client
	openURL    func(string) error
	isTTY      bool
	readSecret func(label string) (string, error) // hidden prompt
	home, cwd  string
	poll       time.Duration // how often a confirmation or a new second step is checked for
	stdinR     *bufio.Reader // see stdin()
}

func main() {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	a := &app{
		in: os.Stdin, out: os.Stdout, err: os.Stderr, getenv: os.Getenv,
		http: &http.Client{Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, // a token never follows a redirect
		openURL: openBrowser, isTTY: isTerminal(os.Stdin), home: home, cwd: cwd, poll: time.Second,
	}
	// the system keychain first; a private file only where there is none
	a.store = newSessionStore(newSystemStore(), a.configDir(), func(m string) { a.say("%s", m) })
	a.readSecret = a.promptHidden
	os.Exit(a.run(os.Args[1:]))
}

// usage is the help: one line per command, "noun verb arguments", then what it does.
const usage = `Usage: ku <command> [options]

  profile add <name> --url <url>             add a server (start here)
  profile use <name>                         switch the active server
  profile list                               list servers
  profile remove <name>                      forget a server and its session
  login                                      sign in to the active server
  link [<app>]                               link this folder to an app (--create: a new one)
  run [name] [tags] -- <command>             run a command with secrets
  secret list [name] [tags]                  list secrets, never their values
  secret set <name> [tags]                   save a value
  secret get <name> [tags]                   reveal a value (--reveal or --out)
  secret update <name|tags> [+tag -tag]      rename, retag or change confirmation
  secret revoke <name|tags>                  block a secret until a new value is saved
  secret archive <name|tags>                 hide a secret
  workspace invite <email>                   invite a person (--machine for CI)
  workspace group <group> +id -id            change group members
  workspace grant <who> <read|write> <tags>  give access to secrets with these tags
  workspace ungrant <who> <tags>             take it away
  workspace disable <identity>               block a person or machine
  workspace enable <identity>                lift the block
  workspace audit [name] [tags]              show who did what
  account factor list                        list your passkeys and authenticator apps
  account factor add <passkey|totp>          add one
  account factor default <id>                offer it first
  account factor remove <id>                 remove one
  version, --version                         print the version

Commands that talk to a server take --profile <name>.
`

func (a *app) run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.err, usage)
		return cli.ExitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "login":
		return a.cmdLogin(rest)
	case "link":
		return a.cmdLink(rest)
	case "profile":
		return a.cmdProfile(rest)
	case "run":
		return a.cmdRun(rest)
	case "secret":
		return a.cmdSecret(rest)
	case "workspace":
		return a.cmdWorkspace(rest)
	case "account":
		return a.cmdAccount(rest)
	case "--version", "version":
		fmt.Fprintln(a.out, version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(a.out, usage)
		return 0
	}
	fmt.Fprint(a.err, usage)
	return cli.ExitUsage
}
