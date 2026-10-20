// Command ku (binary `kuukura`, alias `ku`) is the CLI. Decryption happens on the server;
// the CLI is a secure channel. Values are never accepted as arguments.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
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

// openCommand is the program that opens a URL in the default browser on each OS.
func openCommand(goos, url string) (string, []string) {
	switch goos {
	case "darwin":
		return "open", []string{url}
	case "windows":
		// not `cmd /c start`: the shell would treat & in the URL as a command separator
		return "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		return "xdg-open", []string{url}
	}
}

func openBrowser(url string) error {
	name, args := openCommand(runtime.GOOS, url)
	return exec.Command(name, args...).Start() // #nosec G204 -- fixed binary per OS, the URL is one argument
}

// configRoot is where the per-user configuration lives: $XDG_CONFIG_HOME when set, %AppData% on Windows,
// ~/.config elsewhere (macOS included, as the spec says).
func configRoot(goos, home, xdg, appData string) string {
	switch {
	case xdg != "" && filepath.IsAbs(xdg):
		return xdg
	case goos == "windows" && appData != "":
		return appData
	}
	return filepath.Join(home, ".config")
}

// configDir is <config root>/kuukura. Use XDG_CONFIG_HOME to keep a separate configuration (for tests); do not
// change HOME, because the macOS Keychain lives under it.
func (a *app) configDir() string {
	return filepath.Join(configRoot(runtime.GOOS, a.home, a.getenv("XDG_CONFIG_HOME"), a.getenv("APPDATA")), "kuukura")
}

// say prints a status line to stderr so stdout stays clean for values and pipes.
func (a *app) say(format string, args ...any) { fmt.Fprintf(a.err, format+"\n", args...) }

// nextStep is an error that carries the one command that fixes it; fail prints it on its own line.
type nextStep struct{ msg, run string }

func (e *nextStep) Error() string { return e.msg }

// fail prints "✗ <Sentence.>" on stderr and returns cli.ExitFail. An error argument that is a nextStep adds the line
// with the command that fixes it.
func (a *app) fail(format string, args ...any) int {
	fmt.Fprintf(a.err, "✗ %s\n", cli.Sentence(fmt.Sprintf(format, args...)))
	for _, x := range args {
		var n *nextStep
		if err, ok := x.(error); ok && errors.As(err, &n) {
			fmt.Fprintf(a.err, "  Run: %s\n", n.run)
		}
	}
	return cli.ExitFail
}

// failNext is fail plus the exact command to run next.
func (a *app) failNext(run, format string, args ...any) int {
	a.fail(format, args...)
	fmt.Fprintf(a.err, "  Run: %s\n", run)
	return cli.ExitFail
}

// argFail is fail for an argument that is wrong, which exits like a usage error.
func (a *app) argFail(format string, args ...any) int {
	a.fail(format, args...)
	return cli.ExitUsage
}

// usageFail prints the usage line of the command that got wrong arguments. It never says what was typed: a secret
// passed as an argument by mistake must not come back in the terminal.
func (a *app) usageFail(line string) int {
	fmt.Fprintln(a.err, cli.UsageError(line))
	return cli.ExitUsage
}

// usage is the help: one line per command, "noun verb arguments", then what it does.
const usage = `Usage: ku <command> [options]

  profile add <name> --url <url>             add a server (start here)
  profile use <name>                         switch the active server
  profile list                               list servers
  profile remove <name>                      forget a server and its session
  login                                      sign in to the active server
  link [<app>]                               link this folder to an app
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

// ---- argument parsing ----

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
