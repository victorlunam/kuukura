package api

import (
	"encoding/xml"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

// One mark everywhere: the door (ring r20, eight bolts, amber hub r4.6 on the 14-radius ink tile) is the same drawing
// in the app icon, the logo, the banner, the Dokploy template and the pages; the wordmark is shared by the logo and banner.
// cmd/ku/signedin_test.go pins the CLI page to the same file.
func TestBrandMarkIsOneDrawing(t *testing.T) {
	mark := webFile("assets/mark.svg")
	tile := `<rect width="64" height="64" rx="14" fill="#071519"/>`
	door := []string{
		`<circle cx="32" cy="32" r="20" stroke="#EAF4F2" stroke-width="4.5"/>`,
		`M32 20.5h0M32 43.5h0M20.5 32h0M43.5 32h0M23.87 23.87h0M40.13 23.87h0M23.87 40.13h0M40.13 40.13h0`,
		`<circle cx="32" cy="32" r="4.6" fill="#F5A524"/>`,
	}
	for _, name := range []string{"assets/mark.svg", "assets/logo.svg", "assets/banner.svg"} {
		s := webFile(name)
		for _, p := range door {
			if !strings.Contains(s, p) {
				t.Fatalf("%s lacks the mark geometry %q", name, p)
			}
		}
	}
	if !strings.Contains(mark, tile) || strings.Contains(mark, "<style") || strings.Contains(mark, "id=") {
		t.Fatal("mark.svg is inlined in every page: the tile is pinned and it carries no <style> or ids")
	}
	if b, err := os.ReadFile("../deploy/dokploy/kuukura.svg"); err != nil || string(b) != mark {
		t.Fatalf("deploy/dokploy/kuukura.svg must be a copy of mark.svg (%v)", err)
	}
	fav := webFile("assets/favicon.svg")
	if !strings.Contains(fav, `r="20" stroke="#EAF4F2"`) || !strings.Contains(fav, `r="7" fill="#F5A524"`) || !strings.Contains(fav, "prefers-color-scheme: dark") {
		t.Fatal("favicon: the ring and the amber hub, with a dark-mode tile")
	}
	word := regexp.MustCompile(`d="(M0 -31V0[^"]+)"`)
	logo, banner := word.FindStringSubmatch(webFile("assets/logo.svg")), word.FindStringSubmatch(webFile("assets/banner.svg"))
	if logo == nil || banner == nil || logo[1] != banner[1] {
		t.Fatal("logo and banner must carry the same outlined wordmark")
	}
	if strings.Contains(webFile("assets/logo.svg"), "<text") {
		t.Fatal("the wordmark is outlined paths, never live text")
	}
	if !strings.Contains(webFile("assets/banner.svg"), `viewBox="0 0 1280 640"`) {
		t.Fatal("the banner is 1280x640 (it is also rendered to docs/social-preview.png)")
	}
	if !strings.Contains(string(pageMark), door[2]) {
		t.Fatal("pages must inline mark.svg")
	}
}

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
