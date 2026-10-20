package main

import (
	"strings"
	"testing"
)

// The pages `ku login` leaves in the browser carry the brand mark and the profile name, escaped.
func TestSignedInPageBrand(t *testing.T) {
	page := signedInPage("some_name")
	if !strings.Contains(page, "M32 21.5V32M41.1 37.25 32 32M22.9 37.25 32 32") || !strings.Contains(page, `r="4.2" fill="#F5A524"`) {
		t.Fatal("the mark must be there")
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
