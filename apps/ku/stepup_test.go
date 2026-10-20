package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The OS opens whatever it is given (on Windows a file: or UNC path can launch a program), so ku opens only links
// that point at the profile's own server and shows the rest.
func TestOpenLinkOnlyOpensTheProfilesServer(t *testing.T) {
	var opened []string
	var out strings.Builder
	a := &app{err: &out, openURL: func(u string) error { opened = append(opened, u); return nil }}
	c := &client{a: a, base: "https://vault.example.test"}

	for _, ok := range []string{"https://vault.example.test/stepup?id=1", "https://VAULT.example.test/account/add?id=2"} {
		a.openLink(c, ok)
	}
	if len(opened) != 2 || out.Len() != 0 {
		t.Fatalf("links on the profile's server open: %v %q", opened, out.String())
	}
	for _, bad := range []string{
		"http://vault.example.test/stepup?id=1", // another scheme
		"https://vault.example.test.evil.test/stepup",
		"https://vault.example.test@evil.test/stepup",
		"https://evil.test/stepup",
		"file:///C:/Windows/System32/calc.exe",
		`\\evil.test\share\setup.exe`,
		"",
	} {
		out.Reset()
		a.openLink(c, bad)
		if len(opened) != 2 || !strings.Contains(out.String(), "Not opened") {
			t.Errorf("%q must not be opened: %v %q", bad, opened, out.String())
		}
	}
}

// A server that answers a confirmation request with a foreign link gets its link printed, not opened.
func TestStepUpDoesNotOpenAForeignLink(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			_, _ = w.Write([]byte(`{"id":"x","url":"file:///C:/evil.exe","methods":["passkey"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"done":true}`))
	}))
	defer srv.Close()
	var out strings.Builder
	opened := false
	a := &app{err: &out, http: srv.Client(), poll: time.Millisecond, openURL: func(string) error { opened = true; return nil }}
	id, err := a.stepUp(&client{a: a, base: srv.URL}, "reveal", "A")
	if err != nil || id != "x" {
		t.Fatalf("the confirmation itself still works: %q %v", id, err)
	}
	if opened || !strings.Contains(out.String(), "file:///C:/evil.exe") || !strings.Contains(out.String(), "Not opened") {
		t.Fatalf("the link is shown, not opened: opened=%v %q", opened, out.String())
	}
}

func TestWaitFor(t *testing.T) {
	a := &app{poll: time.Millisecond}

	calls := 0
	if err := a.waitFor(time.Second, func() (bool, error) { calls++; return calls == 3, nil }); err != nil || calls != 3 {
		t.Fatalf("polls until done: %d %v", calls, err)
	}
	boom := errors.New("boom")
	if err := a.waitFor(time.Second, func() (bool, error) { return false, boom }); err != boom {
		t.Fatalf("a failing check stops the wait: %v", err)
	}
	start := time.Now()
	calls = 0
	if err := a.waitFor(50*time.Millisecond, func() (bool, error) { calls++; return false, nil }); !errors.Is(err, errTimeout) {
		t.Fatalf("never done must time out: %v", err)
	}
	if calls < 2 || time.Since(start) > 5*time.Second {
		t.Fatalf("it polled until the deadline: %d calls in %v", calls, time.Since(start))
	}
}

func TestPasskeyLabel(t *testing.T) {
	if passkeyLabel("darwin") != "Touch ID" || passkeyLabel("linux") != "your passkey" || passkeyLabel("windows") != "your passkey" {
		t.Fatal("only macOS has a name for it")
	}
}
