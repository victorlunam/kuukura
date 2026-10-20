package api

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/packages/brand"
)

// The brand's own drawings are pinned in packages/brand; here only what the pages do with them.

func TestPagesInlineTheBrandMark(t *testing.T) {
	if string(pageMark) != brandFile("assets/mark.svg") {
		t.Fatal("pages must inline mark.svg")
	}
}

// The art loses its own <style> inside a page and is themed by the page CSS, so every class an art file uses must
// be defined there, or the picture renders empty.
func TestPageCSSThemesTheArt(t *testing.T) {
	classRE := regexp.MustCompile(`class="([^"]+)"`)
	css := webFile("style.css")
	entries, err := fs.ReadDir(brand.FS, "art")
	if err != nil || len(entries) == 0 {
		t.Fatalf("art: %v", err)
	}
	for _, e := range entries {
		for _, m := range classRE.FindAllStringSubmatch(brandFile("art/"+e.Name()), -1) {
			for _, c := range strings.Fields(m[1]) {
				if c == "pulse" || c == "word" || c == "bg" {
					continue // animation hook / logo-local classes
				}
				if !strings.Contains(css, "."+c) {
					t.Fatalf("art/%s uses class %q that the page CSS does not define (it would render empty inside a page)", e.Name(), c)
				}
			}
		}
	}
	// inside a page the art loses its <style> (the page CSS themes it) but keeps its shapes
	for _, name := range []string{"vault-empty", "passkey", "shield", "done", "alert", "confirm"} {
		out := string(art(name))
		if strings.Contains(out, "<style") || !strings.Contains(out, "<path") && !strings.Contains(out, "<circle") {
			t.Fatalf("art(%s) should be shapes only inside a page", name)
		}
	}
}
