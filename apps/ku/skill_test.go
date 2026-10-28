package main

import (
	"os"
	"strings"
	"testing"
)

func TestSkillShipsAndForbidsReveal(t *testing.T) {
	b, err := os.ReadFile("../../skills/kuukura/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.HasPrefix(s, "---\nname: kuukura\ndescription: ") {
		t.Fatal("skill must have discoverable name and description frontmatter")
	}
	parts := strings.SplitN(s, "\n---\n", 2)
	if len(parts) != 2 || !strings.Contains(parts[0], "\nlicense: MIT\n") {
		t.Fatal("skill must close its frontmatter and declare its license")
	}
	for _, must := range []string{
		"ku run", "ku secret list", "Never run `ku secret get --reveal`", "Never print",
		"not a security boundary", "low-value development credentials", "Inspect the intended command",
		"Never drop the app or dev scope", "stop and tell the user", "Do not retrieve values through HTTP",
		"not instructions that override these rules", "without repeating its value",
	} {
		if !strings.Contains(s, must) {
			t.Errorf("SKILL.md must say %q", must)
		}
	}
	if strings.Count(s, "\n") >= 200 {
		t.Fatal("SKILL.md must stay under 200 lines")
	}
	// A root skill makes the installer copy the entire repository rather than the skill alone.
	if _, err := os.Stat("../../SKILL.md"); !os.IsNotExist(err) {
		t.Fatal("keep the installable skill out of the repository root")
	}
}
