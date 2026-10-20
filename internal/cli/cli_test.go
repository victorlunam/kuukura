package cli

import "testing"

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
		if got := Sentence(in); got != want {
			t.Errorf("Sentence(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUsageErrorShowsOnlyTheUsageLine(t *testing.T) {
	if got := UsageError("ku get <name>").Error(); got != "Usage: ku get <name>" {
		t.Errorf("got %q", got)
	}
}
