package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

// Someone who can write the secrets of an app must not be able to make a teammate's `ku run` load their code:
// a secret named like a loader or interpreter hook is refused, naming it, and the command never starts.
func TestRunRefusesLoaderAndInterpreterHooks(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		w, _ := userWorld(t, p)
		lib := filepath.Join(t.TempDir(), "evil.so")
		if err := os.WriteFile(lib, []byte("FAKE-LIBRARY"), 0o600); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(t.TempDir(), "ran")
		for _, name := range []string{"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "NODE_OPTIONS", "PATH", "PYTHONPATH", "BASH_ENV"} {
			args := []string{"secret", "set", name, "app:shop", "env:hook", "--yes"}
			if name == "LD_PRELOAD" || name == "DYLD_INSERT_LIBRARIES" { // a file secret becomes a path to a library
				args = append(args, "--file", lib)
			}
			mustOK(t, w.ku(fakeValue+"\n", false, nil, args...))
			r := w.ku("", false, nil, "run", name, "env:hook", "--", "touch", marker)
			if r.code != 1 || !strings.Contains(r.errOut, "✗ "+name+" would change how the command loads code") || fileExists(marker) {
				t.Errorf("%s: exit %d, ran=%v\n%s", name, r.code, fileExists(marker), r.errOut)
			}
			noValue(t, r, fakeValue)
		}
		// an ordinary name next to them still works
		mustOK(t, w.ku("v\n", false, nil, "secret", "set", "API_KEY", "app:shop", "env:ok", "--yes"))
		mustOK(t, w.ku("", false, nil, "run", "env:ok", "--", "touch", marker))
		if !fileExists(marker) {
			t.Fatal("a normal secret must be injected")
		}
	})
}
