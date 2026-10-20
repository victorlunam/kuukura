package main

import (
	"path/filepath"
	"testing"
)

func TestConfigRootPerOS(t *testing.T) {
	custom := t.TempDir() // XDG_CONFIG_HOME must be absolute, which "/custom" is not on Windows
	cases := []struct{ goos, home, xdg, appData, want string }{
		{"darwin", "/Users/a", "", "", "/Users/a/.config"},
		{"linux", "/home/a", "", "", "/home/a/.config"},
		{"linux", "/home/a", custom, "", custom},
		{"darwin", "/Users/a", custom, "", custom},
		{"linux", "/home/a", "relative", "", "/home/a/.config"}, // a relative XDG_CONFIG_HOME is ignored
		{"windows", `C:\Users\a`, "", `C:\Users\a\AppData\Roaming`, `C:\Users\a\AppData\Roaming`},
	}
	for _, c := range cases {
		if got := configRoot(c.goos, c.home, c.xdg, c.appData); filepath.ToSlash(got) != filepath.ToSlash(c.want) {
			t.Errorf("%+v: got %q want %q", c, got, c.want)
		}
	}
	// on Windows without APPDATA it still has a place to go
	if got := configRoot("windows", "/home/a", "", ""); filepath.ToSlash(got) != "/home/a/.config" {
		t.Errorf("windows without APPDATA: %q", got)
	}
}
