// Command ku (binary `kuukura`, alias `ku`) is the CLI. Decryption happens on the server;
// the CLI is a secure channel. Values are never accepted as arguments.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// version is set at release time: -ldflags "-X main.version=2026.10.0".
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
	poll       time.Duration // step-up polling interval
}

func main() {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	a := &app{
		in: os.Stdin, out: os.Stdout, err: os.Stderr, getenv: os.Getenv,
		store: newKeychain(),
		http: &http.Client{Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, // a token never follows a redirect
		openURL: openBrowser, isTTY: isTerminal(os.Stdin), home: home, cwd: cwd, poll: time.Second,
	}
	a.readSecret = a.promptHidden
	os.Exit(a.run(os.Args[1:]))
}

func openBrowser(url string) error {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	return exec.Command(name, url).Start() // #nosec G204 -- fixed binary, URL is one argument
}

// configDir is ~/.config/kuukura, or $XDG_CONFIG_HOME/kuukura when that is set. Use XDG_CONFIG_HOME to keep a
// separate configuration (for tests); do not change HOME, because the macOS Keychain lives under it.
func (a *app) configDir() string {
	if x := a.getenv("XDG_CONFIG_HOME"); x != "" && filepath.IsAbs(x) {
		return filepath.Join(x, "kuukura")
	}
	return filepath.Join(a.home, ".config", "kuukura")
}

// say prints a status line to stderr so stdout stays clean for values and pipes.
func (a *app) say(format string, args ...any) { fmt.Fprintf(a.err, format+"\n", args...) }

func (a *app) fail(format string, args ...any) int {
	fmt.Fprintf(a.err, "✗ "+format+"\n", args...)
	return 1
}

const usage = `Usage: ku <command>

  profile add|use|list|remove    manage servers (start here: ku profile add <name> --url <url>)
  login                          sign in to the active profile
  link <app>                     link this folder to an app
  run [name] [tags] -- <cmd>     run a command with secrets
  secret list|set|get|update|revoke|archive
  workspace invite|group|grant|ungrant|remove|audit
`

func (a *app) run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.err, usage)
		return 1
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
	case "--version", "version":
		fmt.Fprintln(a.out, version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(a.out, usage)
		return 0
	}
	fmt.Fprint(a.err, usage)
	return 1
}

// ---- argument parsing ----

type parsed struct {
	pos   []string
	flags map[string]string
}

// parseArgs separates positionals from --flags. valued lists flags that take a value; anything else
// starting with "--" is a boolean. Tokens like +env:qa and -env:prod are positional (tag changes).
func parseArgs(args []string, valued ...string) (parsed, error) {
	p := parsed{flags: map[string]string{}}
	for i := 0; i < len(args); i++ {
		t := args[i]
		if !strings.HasPrefix(t, "--") || t == "--" {
			p.pos = append(p.pos, t)
			continue
		}
		name, val, hasVal := strings.Cut(strings.TrimPrefix(t, "--"), "=")
		isValued := false
		for _, v := range valued {
			isValued = isValued || v == name
		}
		switch {
		case isValued && hasVal:
			p.flags[name] = val
		case isValued && i+1 < len(args):
			i++
			p.flags[name] = args[i]
		case isValued:
			return p, fmt.Errorf("--%s needs a value", name)
		default:
			p.flags[name] = "true"
		}
	}
	return p, nil
}

func (p parsed) has(name string) bool { _, ok := p.flags[name]; return ok }

// selectorFrom turns positionals into a name (first, no colon) and tags (key:value).
func selectorFrom(pos []string) (name string, tags []string, err error) {
	for i, t := range pos {
		switch {
		case strings.Contains(t, ":"):
			tags = append(tags, strings.ToLower(t))
		case i == 0:
			name = strings.ToUpper(t)
		default:
			return "", nil, fmt.Errorf("%q is not a tag. Tags look like key:value", t)
		}
	}
	return name, tags, nil
}

var tagPartRE = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
