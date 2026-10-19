package api

import (
	"encoding/xml"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// Every brand SVG must render on its own (opened directly or used as <img>) and inside the pages.
// An art file that uses a class its own <style> does not define renders as an empty picture.
func TestSVGsAreSelfContainedAndThemed(t *testing.T) {
	classRE := regexp.MustCompile(`class="([^"]+)"`)
	defRE := regexp.MustCompile(`\.([a-z][a-z0-9-]*)\s*\{`)
	pageCSS := webFile("style.css")

	check := func(path string) {
		b, err := fs.ReadFile(webFS, path)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		var v struct{ XMLName xml.Name }
		if err := xml.Unmarshal(b, &v); err != nil || v.XMLName.Local != "svg" {
			t.Fatalf("%s is not well-formed SVG: %v", path, err)
		}
		if !strings.Contains(s, `xmlns="http://www.w3.org/2000/svg"`) || !strings.Contains(s, "viewBox=") {
			t.Fatalf("%s needs xmlns and viewBox to render standalone", path)
		}
		if strings.Contains(s, "http://") && strings.Count(s, "http://") > 1 || strings.Contains(s, "https://") {
			t.Fatalf("%s references an external resource", path)
		}
		style := ""
		if i := strings.Index(s, "<style>"); i >= 0 {
			style = s[i : i+strings.Index(s[i:], "</style>")]
		}
		defined := map[string]bool{}
		for _, m := range defRE.FindAllStringSubmatch(style, -1) {
			defined[m[1]] = true
		}
		for _, m := range classRE.FindAllStringSubmatch(s, -1) {
			for _, c := range strings.Fields(m[1]) {
				if c == "pulse" || c == "word" || c == "bg" {
					continue // animation hook / logo-local classes
				}
				if !defined[c] {
					t.Fatalf("%s uses class %q that its own <style> does not define (it would render empty)", path, c)
				}
				if strings.HasPrefix(path, "web/art/") && !strings.Contains(pageCSS, "."+c) {
					t.Fatalf("%s uses class %q that the page CSS does not define (it would render empty inside a page)", path, c)
				}
			}
		}
	}

	for _, dir := range []string{"web/art", "web/assets"} {
		entries, err := fs.ReadDir(webFS, dir)
		if err != nil || len(entries) == 0 {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, e := range entries {
			check(dir + "/" + e.Name())
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
