package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/victorlunam/kuukura/internal/cli"
)

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

func splitItem(item string) (name string, tags []string) {
	f := strings.Fields(item)
	if len(f) == 0 {
		return "", nil
	}
	return f[0], f[1:]
}

// itemLines renders "NAME  tag tag" rows with aligned names.
func itemLines(items []string, indent string) string {
	w := 0
	for _, it := range items {
		n, _ := splitItem(it)
		w = max(w, len(n))
	}
	var b strings.Builder
	for _, it := range items {
		n, t := splitItem(it)
		fmt.Fprintf(&b, "%s%-*s  %s\n", indent, w, n, strings.Join(t, " "))
	}
	return strings.TrimRight(b.String(), "\n")
}

// distinguishingTag finds a tag of the first item that not every item has, to suggest in a hint.
func distinguishingTag(items []string) string {
	if len(items) < 2 {
		return "key:value"
	}
	_, first := splitItem(items[0])
	for _, t := range first {
		all := true
		for _, it := range items[1:] {
			_, ts := splitItem(it)
			all = all && slices.Contains(ts, t)
		}
		if !all {
			return t
		}
	}
	return "key:value"
}

// report prints an error in plain copy and returns exit code 1. hint builds the suggestion line for an
// ambiguous selection from a distinguishing tag.
func (a *app) report(err error, hint func(tag string) string) int {
	var p *problem
	if !errors.As(err, &p) {
		return a.fail("%v", err)
	}
	switch p.Code {
	case "ambiguous":
		name, same := "", true
		for i, it := range p.Items {
			n, _ := splitItem(it)
			if i == 0 {
				name = n
			}
			same = same && n == name
		}
		if same && name != "" {
			a.fail("%d secrets are called %s:", len(p.Items), name)
		} else {
			a.fail("%d secrets match:", len(p.Items))
		}
		fmt.Fprintln(a.err, itemLines(p.Items, "    "))
		fmt.Fprintf(a.err, "  Add or remove a tag to pick one, for example: %s\n", hint(distinguishingTag(p.Items)))
		return 1
	case "blocked":
		for _, it := range p.Items {
			n, t := splitItem(it)
			a.failNext("ku secret set "+strings.TrimSpace(n+" "+strings.Join(t, " ")), "%s is blocked until you save a new value", n)
		}
		return cli.ExitFail
	case "forbidden":
		if len(p.Items) > 0 {
			a.fail("You don't have access to:")
			fmt.Fprintln(a.err, itemLines(p.Items, "    "))
			return 1
		}
	}
	if p.Code == "unauthorized" {
		return a.failNext("ku login", "%s", plain(err))
	}
	return a.fail("%s", plain(err))
}
