package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// markShapes is the drawing inside packages/brand/assets/mark.svg (the web pages inline that file), without the
// <svg> wrapper and without the whitespace between tags.
func markShapes(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../packages/brand/assets/mark.svg")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	s = s[strings.Index(s, ">")+1 : strings.LastIndex(s, "</svg>")]
	return regexp.MustCompile(`>\s+<`).ReplaceAllString(strings.TrimSpace(s), "><")
}

// The pages `ku login` leaves in the browser carry the brand mark and the profile name, escaped.
func TestSignedInPageBrand(t *testing.T) {
	page := signedInPage("some_name")
	// the CLI page and the web pages must draw the same mark: this copy is the file's shapes, byte for byte
	if want := markShapes(t); !strings.Contains(page, want) || !strings.Contains(want, `fill="#F5A524"`) {
		t.Fatalf("the CLI page must carry packages/brand/assets/mark.svg exactly:\n%s", want)
	}
	if !strings.Contains(page, "<small>some_name</small>") || !strings.Contains(page, "You're signed in") {
		t.Fatal("profile name and message")
	}
	if strings.Contains(signedInPage(`<script>x</script>`), "<script>x") {
		t.Fatal("the profile name must be HTML-escaped")
	}
}

func TestSignInFailedPageSaysSo(t *testing.T) {
	page := signInFailedPage("some_name")
	if !strings.Contains(page, "Sign-in did not finish") || strings.Contains(page, "signed in") || !strings.Contains(page, "<small>some_name</small>") {
		t.Fatal("the failure page says it failed and still names the profile")
	}
}
