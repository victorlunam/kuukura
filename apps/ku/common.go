package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
)

type selReq struct {
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags"`
}

// stdin is the one buffered reader of a.in, so a second prompt does not lose what the first one buffered.
func (a *app) stdin() *bufio.Reader {
	if a.stdinR == nil {
		a.stdinR = bufio.NewReader(a.in)
	}
	return a.stdinR
}

// confirm asks a y/N question. --yes skips it; without a terminal it refuses rather than guessing.
func (a *app) confirm(question string, yes bool) (bool, error) {
	if yes {
		return true, nil
	}
	if !a.isTTY {
		return false, errors.New("add --yes to confirm when there is no terminal")
	}
	fmt.Fprintf(a.err, "%s (y/N) ", question)
	line, _ := a.stdin().ReadString('\n')
	l := strings.ToLower(strings.TrimSpace(line))
	return l == "y" || l == "yes", nil
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
		return exitFail
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

func writePrivate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the user chose this path
	if err != nil {
		return err
	}
	return fillPrivate(f, data)
}

// fillPrivate writes data to a freshly opened file, forces mode 0600 (an existing file keeps its old mode
// otherwise) and closes it.
func fillPrivate(f *os.File, data []byte) error {
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
