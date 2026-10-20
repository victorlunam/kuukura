package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
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
	if len(command) == 0 {
		return a.fail("Use: ku run [name] [tags] -- <command>")
	}
	p, err := parseArgs(before, []string{"profile"})
	if err != nil {
		return a.fail("%v", err)
	}
	name, tags, err := selectorFrom(p.pos)
	if err != nil {
		return a.fail("%v.", err)
	}
	c, pr, err := a.withProfile(p.flags["profile"], true)
	if err != nil {
		return a.fail("%v.", err)
	}
	if pr.app != "" && !hasKey(tags, "app") {
		tags = append(tags, "app:"+pr.app)
	}
	if len(tags) == 0 {
		a.fail("This folder is not linked to an app.")
		hint := "  Run: ku link <app>"
		if apps := a.knownApps(c); len(apps) > 0 {
			hint += "   (your apps: " + strings.Join(apps, ", ") + ")"
		}
		fmt.Fprintln(a.err, hint)
		return 1
	}

	var res struct {
		Secrets []valueResp `json:"secrets"`
	}
	sel := selReq{name, tags}
	if err := a.callStepUp(c, "run", subjectOf(name, tags), "POST", "/run", sel, &res); err != nil {
		return a.report(err, func(t string) string {
			return joinWords("ku run", name, t, "--", strings.Join(command, " "))
		})
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

func (a *app) exec(command, env []string) int {
	cmd := exec.Command(command[0], command[1:]...) // #nosec G204 G702 -- running the user's own command is the point
	cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, a.in, a.out, a.err
	if err := cmd.Start(); err != nil {
		return a.fail("Could not start %s.", command[0])
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for {
		select {
		case s := <-sigs:
			_ = cmd.Process.Signal(s)
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
	for _, t := range tags {
		if strings.HasPrefix(t, key+":") {
			return true
		}
	}
	return false
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
