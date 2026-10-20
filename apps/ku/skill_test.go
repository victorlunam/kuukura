package main

import (
	"os"
	"strings"
	"testing"
)

func TestSkillShipsAndForbidsReveal(t *testing.T) {
	b, err := os.ReadFile("../../SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, must := range []string{"ku run", "ku secret list", "Never run `ku secret get --reveal`", "Never print"} {
		if !strings.Contains(s, must) {
			t.Fatalf("SKILL.md must say %q", must)
		}
	}
	if strings.Count(s, "\n") > 40 {
		t.Fatal("SKILL.md must stay short")
	}
}
