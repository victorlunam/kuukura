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

// pickers returns, for each item, the fewest tags that leave only that item among the ones listed ("tag" for one it
// has and some other lacks, "~tag" for one it lacks and some other has), several separated by spaces when one is not
// enough. Two secrets of one name never have the same tags, so every item can be told apart from every other.
// It is a greedy cover: each step takes the tag that rules out the most of the items still left, a tag the item
// has first on a tie.
func pickers(items []string) []string {
	tags := make([][]string, len(items))
	for i, it := range items {
		_, tags[i] = splitItem(it)
	}
	picks := make([]string, len(items))
	for i, ts := range tags {
		var left []int // the others no tag chosen so far rules out
		for j := range tags {
			if j != i {
				left = append(left, j)
			}
		}
		var chosen []string
		for len(left) > 0 {
			best, bestN := "", 0
			var bestRules func(o []string) bool
			try := func(tok string, rules func(o []string) bool) {
				n := 0
				for _, j := range left {
					if rules(tags[j]) {
						n++
					}
				}
				if n > bestN {
					best, bestN, bestRules = tok, n, rules
				}
			}
			for _, t := range ts { // a tag the item has rules out the others that lack it
				try(t, func(o []string) bool { return !slices.Contains(o, t) })
			}
			for _, j := range left { // a tag it lacks rules out the others that have it
				for _, t := range tags[j] {
					if !slices.Contains(ts, t) {
						try(notMark+t, func(o []string) bool { return slices.Contains(o, t) })
					}
				}
			}
			if bestN == 0 { // identical tags: cannot happen for secrets of one name
				chosen = nil
				break
			}
			chosen = append(chosen, best)
			left = slices.DeleteFunc(left, func(j int) bool { return bestRules(tags[j]) })
		}
		picks[i] = strings.Join(chosen, " ")
	}
	return picks
}

// withMatches adds to an ambiguity error everything the selector matches, so the hint can say what a suggested tag
// would leave out. Best effort: without the list the hint is the same, minus that note.
func (a *app) withMatches(c *client, err error, name string, tags []string) error {
	var p *problem
	if !errors.As(err, &p) || p.Code != "ambiguous" {
		return err
	}
	rows, lerr := a.listSecrets(c, name, tags)
	if lerr != nil {
		return err
	}
	for _, r := range rows {
		p.matched = append(p.matched, strings.TrimSpace(r.Name+" "+strings.Join(r.Tags, " ")))
	}
	return err
}

// leavesOut is the names that matched but would not once pick (tags, "~tag" for an excluded one) is added: a name all of whose
// secrets lack the tag (or have it, for "~tag") silently disappears from `ku run`, so the hint must say so.
func leavesOut(matched []string, pick string) []string {
	before, after := map[string]bool{}, map[string]bool{}
	for _, it := range matched {
		n, ts := splitItem(it)
		before[n] = true
		keep := true // pick is one or more tags: all of them must hold
		for _, tok := range strings.Fields(pick) {
			if t, neg := strings.CutPrefix(tok, notMark); neg {
				keep = keep && !slices.Contains(ts, t)
			} else {
				keep = keep && slices.Contains(ts, tok)
			}
		}
		if keep {
			after[n] = true
		}
	}
	var lost []string
	for n := range before {
		if !after[n] {
			lost = append(lost, n)
		}
	}
	slices.Sort(lost)
	return lost
}

// pickLines renders the ambiguous secrets as "NAME  tags  add <pick> to pick this one", aligned, so each row says
// which tag picks it, and which other secrets that tag would leave out.
func pickLines(items, picks []string, lost [][]string, indent string) string {
	nw, tw := 0, 0
	rows := make([][2]string, len(items))
	for i, it := range items {
		n, t := splitItem(it)
		rows[i] = [2]string{n, strings.Join(t, " ")}
		nw, tw = max(nw, len(n)), max(tw, len(rows[i][1]))
	}
	lines := make([]string, len(rows))
	for i, r := range rows {
		lines[i] = fmt.Sprintf("%s%-*s  %-*s", indent, nw, r[0], tw, r[1])
		if picks[i] != "" {
			lines[i] += fmt.Sprintf("  add %s to pick this one", picks[i])
			if len(lost[i]) > 0 {
				lines[i] += fmt.Sprintf(" (also leaves out %s)", strings.Join(lost[i], ", "))
			}
		}
		lines[i] = strings.TrimRight(lines[i], " ")
	}
	return strings.Join(lines, "\n")
}

// reportWrite is report for a write: a denial says which tags the write was for and how to get access. Tags and
// names are fine to print; a value never is.
func (a *app) reportWrite(err error, tags []string) int {
	var p *problem
	if errors.As(err, &p) && p.Code == "forbidden" && len(p.Items) == 0 && len(tags) > 0 {
		t := strings.Join(tags, " ")
		a.fail("You can't write secrets tagged %s", t)
		fmt.Fprintf(a.err, "  Ask an admin: ku workspace grant <you> write %s\n", t)
		return cli.ExitFail
	}
	return a.report(err, nil)
}

// report prints an error in plain copy and returns exit code 1. For an ambiguous selection every row says which tag
// picks it, and hint (nil: none) builds the whole command with the first such tag, from what the person typed.
func (a *app) report(err error, hint func(pick string) string) int {
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
		picks := pickers(p.Items)
		lost := make([][]string, len(picks))
		for i, pk := range picks {
			if pk != "" {
				lost[i] = leavesOut(p.matched, pk)
			}
		}
		fmt.Fprintln(a.err, pickLines(p.Items, picks, lost, "    "))
		// the example uses a tag that leaves nothing else out; if every one does, the first (the rows say what)
		first := ""
		for i, pk := range picks {
			if pk == "" {
				continue
			}
			if first == "" {
				first = pk
			}
			if len(lost[i]) == 0 {
				first = pk
				break
			}
		}
		switch {
		case first != "" && hint != nil:
			fmt.Fprintf(a.err, "  For example: %s\n", hint(first))
		case first == "":
			fmt.Fprintln(a.err, "  Add a tag (key:value), or leave one out with ~key:value, to pick one.")
		}
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
