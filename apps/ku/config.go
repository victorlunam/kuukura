package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// configRoot is where the per-user configuration lives: $XDG_CONFIG_HOME when set, %AppData% on Windows,
// ~/.config elsewhere (macOS included, as the spec says).
func configRoot(goos, home, xdg, appData string) string {
	switch {
	case xdg != "" && filepath.IsAbs(xdg):
		return xdg
	case goos == "windows" && appData != "":
		return appData
	}
	return filepath.Join(home, ".config")
}

// configDir is <config root>/kuukura. Use XDG_CONFIG_HOME to keep a separate configuration (for tests); do not
// change HOME, because the macOS Keychain lives under it.
func (a *app) configDir() string {
	return filepath.Join(configRoot(runtime.GOOS, a.home, a.getenv("XDG_CONFIG_HOME"), a.getenv("APPDATA")), "kuukura")
}

// config.toml holds profiles (server URL only, never a secret); links.json maps folders to apps.
type configFile struct {
	Active   string                `toml:"active"`
	Profiles map[string]profileCfg `toml:"profiles"`
}

type profileCfg struct {
	URL string `toml:"url"`
}

type link struct {
	App     string `json:"app"`
	Profile string `json:"profile,omitempty"`
}

// A profile name starts with a letter or digit, so it can never be "." or ".." (it is also a file name).
var profileRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

func (a *app) loadConfig() (configFile, error) {
	var c configFile
	b, err := os.ReadFile(filepath.Join(a.configDir(), "config.toml")) // #nosec G304 -- fixed path under the user's home
	if errors.Is(err, os.ErrNotExist) {
		return configFile{Profiles: map[string]profileCfg{}}, nil
	}
	if err != nil {
		return c, err
	}
	if err := toml.Unmarshal(b, &c); err != nil {
		return c, errors.New("config.toml is not valid")
	}
	if c.Profiles == nil {
		c.Profiles = map[string]profileCfg{}
	}
	return c, nil
}

func (a *app) saveConfig(c configFile) error {
	if err := os.MkdirAll(a.configDir(), 0o700); err != nil {
		return err
	}
	b, err := toml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(a.configDir(), "config.toml"), b, 0o600)
}

func (a *app) loadLinks() (map[string]link, error) {
	links := map[string]link{}
	b, err := os.ReadFile(filepath.Join(a.configDir(), "links.json")) // #nosec G304 -- fixed path under the user's home
	if errors.Is(err, os.ErrNotExist) {
		return links, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &links); err != nil {
		return nil, errors.New("links.json is not valid")
	}
	return links, nil
}

func (a *app) saveLinks(l map[string]link) error {
	if err := os.MkdirAll(a.configDir(), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(l, "", "  ")
	return os.WriteFile(filepath.Join(a.configDir(), "links.json"), b, 0o600)
}

// currentLink returns the nearest parent folder link of dir.
func (a *app) currentLink(dir string) (link, bool, error) {
	links, err := a.loadLinks()
	if err != nil {
		return link{}, false, err
	}
	for d := dir; ; d = filepath.Dir(d) {
		if l, ok := links[d]; ok {
			return l, true, nil
		}
		if d == filepath.Dir(d) {
			return link{}, false, nil
		}
	}
}

func validateURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	local := u != nil && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
	if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && local)) || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("the server URL must look like https://vault.example.com")
	}
	return u.String(), nil
}

// profile is the resolved server and session for one command.
type profile struct {
	name      string
	url       string
	token     string // empty until read from the session store (or KU_TOKEN)
	ephemeral bool   // KU_URL: no config file, no saved session
	app       string // linked app of the current folder, if any
}

// resolve: --profile > KU_URL/KU_TOKEN or KU_PROFILE > folder link profile > active profile.
func (a *app) resolve(flagProfile string) (profile, error) {
	kuURL, kuProfile := a.getenv("KU_URL"), a.getenv("KU_PROFILE")
	if kuURL != "" && kuProfile != "" {
		return profile{}, errors.New("set either KU_URL or KU_PROFILE, not both")
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return profile{}, err
	}
	lk, linked, err := a.currentLink(a.cwd)
	if err != nil {
		return profile{}, err
	}
	p := profile{}
	if linked {
		p.app = lk.App
	}
	named := func(name string) (profile, error) {
		pc, ok := cfg.Profiles[name]
		if !ok {
			return profile{}, &nextStep{fmt.Sprintf("Unknown profile %s.", name), "ku profile add " + name + " --url <url>"}
		}
		p.name, p.url = name, pc.URL
		return p, nil
	}
	switch {
	case flagProfile != "":
		return named(flagProfile)
	case kuURL != "":
		u, err := validateURL(kuURL)
		if err != nil {
			return profile{}, err
		}
		p.name, p.url, p.token, p.ephemeral = "(env)", u, a.getenv("KU_TOKEN"), true
		return p, nil
	case kuProfile != "":
		return named(kuProfile)
	case linked && lk.Profile != "":
		return named(lk.Profile)
	case cfg.Active != "":
		return named(cfg.Active)
	}
	return profile{}, &nextStep{"No server yet.", "ku profile add <name> --url https://your-server"}
}

func sortedKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }
