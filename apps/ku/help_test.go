package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/apps/ku-server/api"
)

// A problem code added to the API without a message in plain() would reach people as "Something went wrong".
func TestPlainSaysSomethingSpecificForEveryProblemCode(t *testing.T) {
	generic := plain(&problem{Code: "internal"})
	for _, code := range api.Codes() {
		msg := plain(&problem{Code: code, retryAfter: "7"})
		if code != "internal" && msg == generic {
			t.Errorf("plain has no message for the API code %q", code)
		}
		if sentence(msg) != msg {
			t.Errorf("%s: %q is not a sentence (capital, final period)", code, msg)
		}
		if code != "unauthorized" && strings.Contains(msg, "ku login") {
			t.Errorf("%s: the next command goes on its own line, not in the sentence: %q", code, msg)
		}
	}
	// the server's own detail wins where it says more than the code, and the result is still a sentence
	if got := plain(&problem{Code: "conflict", Detail: "that name is already used"}); got != "That name is already used." {
		t.Errorf("detail: %q", got)
	}
}

func TestSentence(t *testing.T) {
	for in, want := range map[string]string{
		"you are not logged in":     "You are not logged in.",
		"Already a sentence.":       "Already a sentence.",
		"3 secrets match:":          "3 secrets match:",
		"  spaced out  ":            "Spaced out.",
		"Is it?":                    "Is it?",
		"":                          "",
		"ünïcode first letter":      "Ünïcode first letter.",
		"ends with detail: no stop": "Ends with detail: no stop.",
	} {
		if got := sentence(in); got != want {
			t.Errorf("sentence(%q) = %q, want %q", in, got, want)
		}
	}
}

var verbWord = regexp.MustCompile(`^[a-z]+$`)

// Every help line is "noun verb arguments", then the description at one column.
func TestHelpIsAlignedAndMatchesTheDispatcher(t *testing.T) {
	col, verbs := -1, map[string][]string{}
	for l := range strings.SplitSeq(usage, "\n") {
		if !strings.HasPrefix(l, "  ") {
			continue
		}
		i := strings.Index(l[2:], "  ")
		if i < 0 {
			t.Fatalf("no description on %q", l)
		}
		i += 2
		j := i + len(l[i:]) - len(strings.TrimLeft(l[i:], " "))
		if col == -1 {
			col = j
		}
		if j != col {
			t.Errorf("description of %q starts at column %d, not %d", l, j, col)
		}
		words := strings.Fields(l[:i])
		if len(words) > 1 && verbWord.MatchString(words[1]) {
			verbs[words[0]] = append(verbs[words[0]], words[1])
		}
	}
	// `ku <noun>` without a verb answers with its verbs: they are the ones the help lists
	for noun, listed := range verbs {
		if noun == "run" || noun == "account" {
			continue // run has no verbs; account has one noun more, checked below
		}
		a, _, out := testApp(t, nil)
		if code := a.run([]string{noun}); code != exitUsage {
			t.Errorf("ku %s: exit %d", noun, code)
		}
		want := "Usage: ku " + noun + " " + strings.Join(listed, "|") + "\n"
		if out.String() != want {
			t.Errorf("ku %s says %q, the help lists %q", noun, out.String(), want)
		}
	}
	a, _, out := testApp(t, nil)
	if a.run([]string{"account"}) != exitUsage || !strings.HasPrefix(out.String(), "Usage: ku account factor ") {
		t.Errorf("ku account: %q", out.String())
	}
}

func TestUsageErrorsExitTwo(t *testing.T) {
	a, _, out := testApp(t, nil)
	for _, args := range [][]string{{}, {"nonsense"}, {"profile"}, {"profile", "use"}, {"profile", "add", "x"}, {"workspace", "disable"}} {
		out.Reset()
		if code := a.run(args); code != exitUsage {
			t.Errorf("%v: exit %d, %q", args, code, out.String())
		}
	}
	out.Reset()
	if code := a.run([]string{"help"}); code != 0 || !strings.HasPrefix(out.String(), "Usage: ku <command>") {
		t.Errorf("help: %d %q", code, out.String())
	}
}
