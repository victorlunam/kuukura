package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/victorlunam/kuukura/internal/cli"
)

// cmdRun injects every selected secret the identity can read into the command's environment.
// It fails closed, before starting the command, if anything is blocked, not permitted or ambiguous.
func (a *app) cmdRun(args []string) int {
	var before, command []string
	for i, t := range args {
		if t == "--" {
			before, command = args[:i], args[i+1:]
			break
		}
	}
	const runUsage = "ku run [name] [tags] [--profile <name>] -- <command>"
	if len(command) == 0 {
		return a.usageFail(runUsage)
	}
	p, ok := a.parse(runUsage, before, []string{"profile"})
	if !ok {
		return cli.ExitUsage
	}
	name, tags, err := selectorFrom(p.pos)
	if err != nil {
		return a.argFail("%v", err)
	}
	c, pr, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v", err)
	}
	tags = a.withApp(pr, tags)
	if len(tags) == 0 {
		a.fail("This folder is not linked to an app")
		hint := "  Run: ku link <app>"
		if apps := a.knownApps(c); len(apps) > 0 {
			hint += "   (your apps: " + strings.Join(apps, ", ") + ")"
		}
		fmt.Fprintln(a.err, hint)
		return cli.ExitFail
	}

	var res struct {
		Secrets []valueResp `json:"secrets"`
	}
	sel := newSel(name, tags)
	if err := a.callStepUp(c, "run", subjectOf(name, tags), "POST", "/run", sel, &res); err != nil {
		return a.report(err, func(t string) string {
			return joinWords("ku run", name, t, "--", strings.Join(command, " "))
		})
	}

	for _, s := range res.Secrets {
		if isHookVar(s.Name) {
			return a.fail("%s would change how the command loads code, so it is not injected and nothing was run. Rename that secret.", s.Name)
		}
	}
	env := os.Environ()
	var tmp string
	defer func() {
		if tmp != "" {
			_ = os.RemoveAll(tmp)
		}
	}()
	for _, s := range res.Secrets {
		data, err := s.bytes()
		if err != nil {
			return a.fail("The server sent something unreadable.")
		}
		if s.Kind != "file" {
			env = append(env, s.Name+"="+string(data))
			continue
		}
		if tmp == "" {
			if tmp, err = os.MkdirTemp("", "ku-"); err != nil { // 0700
				return a.fail("Could not create a private folder for file secrets.")
			}
		}
		path := filepath.Join(tmp, s.Name+"-"+filepath.Base(s.Filename))
		if err := writePrivate(path, data); err != nil {
			return a.fail("Could not write the file for %s.", s.Name)
		}
		env = append(env, s.Name+"="+path)
	}
	return a.exec(command, env)
}

// hookVars are names whose value makes a program load or run code: the dynamic loader and the common interpreters
// read them at start. Whoever can write a secret of an app could otherwise store one (a file secret even gives a
// path to a library of their choosing) and run code on every teammate's `ku run`. Any DYLD_* name counts. The list
// is the usual vectors, not a sandbox: the command itself is the user's own.
var hookVars = []string{
	"PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "BASH_ENV",
	"NODE_OPTIONS", "PYTHONPATH", "PYTHONSTARTUP", "RUBYOPT", "RUBYLIB", "PERL5OPT", "PERL5LIB", "JAVA_TOOL_OPTIONS",
}

func isHookVar(name string) bool {
	return slices.Contains(hookVars, name) || strings.HasPrefix(name, "DYLD_")
}

func (a *app) exec(command, env []string) int {
	cmd := exec.Command(command[0], command[1:]...) // #nosec G204 G702 -- running the user's own command is the point
	cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, a.in, a.out, a.err
	// Registered before the start so no signal can kill ku while the command lives on with secrets in its environment.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		return a.fail("Could not start %s.", command[0])
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for {
		select {
		case s := <-sigs:
			// Ctrl-C reaches the command from the terminal itself (same process group, same console on Windows);
			// forwarding it too would be a second interrupt, which many dev servers take as "force quit".
			if s != os.Interrupt {
				_ = cmd.Process.Signal(s)
			}
		case err := <-done:
			var ee *exec.ExitError
			switch {
			case err == nil:
				return 0
			case errors.As(err, &ee):
				if ee.ExitCode() >= 0 {
					return ee.ExitCode()
				}
				return 128 + int(ee.Sys().(syscall.WaitStatus).Signal()) // killed by a signal
			}
			return 1
		}
	}
}

func hasKey(tags []string, key string) bool {
	return slices.ContainsFunc(tags, func(t string) bool { return strings.HasPrefix(t, key+":") })
}

// knownApps lists app:* tag values the identity can see, for the "not linked" hint.
func (a *app) knownApps(c *client) []string {
	rows, err := a.listSecrets(c, "", nil)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	for _, r := range rows {
		for _, t := range r.Tags {
			if v, ok := strings.CutPrefix(t, "app:"); ok {
				seen[v] = true
			}
		}
	}
	return sortedKeys(seen)
}

// joinWords joins the non-empty words with single spaces.
func joinWords(w ...string) string {
	var out []string
	for _, x := range w {
		if x != "" {
			out = append(out, x)
		}
	}
	return strings.Join(out, " ")
}
