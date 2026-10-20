package api

import (
	"regexp"
	"testing"
)

// packages/brand/tokens.css is the brand's source of truth and style.css repeats its :root values (the page CSS is
// inlined under a nonce, so it cannot import a file). Both must declare the same variables, light and dark.
func TestStyleTokensEqualBrandTokens(t *testing.T) {
	rootBlock := regexp.MustCompile(`:root\s*\{([^}]*)\}`)
	decl := regexp.MustCompile(`(--[a-z0-9-]+|color-scheme):\s*([^;]+);`)
	parse := func(css string) []map[string]string {
		var blocks []map[string]string
		for _, b := range rootBlock.FindAllStringSubmatch(css, -1) {
			vars := map[string]string{}
			for _, d := range decl.FindAllStringSubmatch(b[1], -1) {
				vars[d[1]] = d[2]
			}
			blocks = append(blocks, vars)
		}
		return blocks
	}
	want, got := parse(brandFile("tokens.css")), parse(webFile("style.css"))
	if len(want) != 2 || len(got) != 2 {
		t.Fatalf(":root blocks (light, dark): tokens.css has %d, style.css has %d, want 2 each", len(want), len(got))
	}
	for i, theme := range []string{"light", "dark"} {
		for k, v := range want[i] {
			if got[i][k] != v {
				t.Errorf("%s %s: style.css has %q, packages/brand/tokens.css has %q", theme, k, got[i][k], v)
			}
		}
		for k := range got[i] {
			if _, ok := want[i][k]; !ok {
				t.Errorf("%s %s is in style.css but not in packages/brand/tokens.css", theme, k)
			}
		}
	}
}
