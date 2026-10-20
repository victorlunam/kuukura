package main

import (
	"strings"
	"testing"
)

func TestOpenCommandPerOS(t *testing.T) {
	u := "http://localhost:8080/auth/login?cli_port=1&cli_state=s"
	for goos, want := range map[string][]string{
		"darwin":  {"open", u},
		"linux":   {"xdg-open", u},
		"windows": {"rundll32", "url.dll,FileProtocolHandler", u},
	} {
		name, args := openCommand(goos, u)
		got := append([]string{name}, args...)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s: got %v want %v", goos, got, want)
		}
	}
	// the URL is always one argument (the & of a query string must never reach a shell)
	if _, args := openCommand("windows", u); args[len(args)-1] != u {
		t.Error("the URL must stay a single argument")
	}
}
