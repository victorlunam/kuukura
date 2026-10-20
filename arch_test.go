package kuukura_test

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// The dependency rules of CONTRIBUTING.md ("Repository layout"), checked on the imports of every package's
// non-test code (tests may wire a real server and database to drive a CLI end to end).
const module = "github.com/victorlunam/kuukura/"

// allowed lists, per internal domain package (and packages/brand), the other local packages it may import.
// Layering goes downward only: storage and keys are leaves.
var allowed = map[string][]string{
	"internal/storage":   {},
	"internal/keys":      {},
	"internal/cli":       {},
	"packages/brand":     {},
	"internal/audit":     {"internal/storage"},
	"internal/access":    {"internal/audit", "internal/storage"},
	"internal/auth":      {"internal/audit", "internal/keys", "internal/storage"},
	"internal/secrets":   {"internal/access", "internal/audit", "internal/keys", "internal/storage"},
	"internal/identity":  {"internal/access", "internal/audit", "internal/auth", "internal/storage"},
	"internal/masterkey": {"internal/audit", "internal/auth", "internal/keys", "internal/secrets", "internal/storage"},
}

// stdlibOnly packages import nothing outside the standard library.
var stdlibOnly = []string{"internal/cli", "packages/brand"}

// sqlPackages are the only packages that may import database/sql. Apps must not.
var sqlPackages = []string{
	"internal/storage", "internal/audit", "internal/access", "internal/auth", "internal/identity", "internal/secrets",
	"internal/masterkey",
}

// unit is the package a rule talks about: "apps/ku-server/api" is part of "apps/ku-server", "internal/auth/authtest"
// of "internal/auth".
func unit(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 2 && (parts[0] == "apps" || parts[0] == "internal" || parts[0] == "packages") {
		parts = parts[:2]
	}
	return strings.Join(parts, "/")
}

func TestDependencyRules(t *testing.T) {
	out, err := exec.Command("go", "list", "-json", "./...").Output()
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var p struct {
			ImportPath string
			Imports    []string
		}
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		from := strings.TrimPrefix(p.ImportPath, module)
		fromUnit := unit(from)
		rule, ruled := allowed[fromUnit]
		if !ruled && strings.HasPrefix(fromUnit, "internal/") {
			t.Errorf("%s: no layering rule for %s; add it to `allowed` in arch_test.go", from, fromUnit)
		}
		for _, imp := range p.Imports {
			to := strings.TrimPrefix(imp, module)
			local := to != imp
			toUnit := unit(to)
			switch {
			case imp == "database/sql" && !slices.Contains(sqlPackages, fromUnit):
				t.Errorf("%s imports database/sql: SQL belongs in internal/storage and the domain packages, never here", from)
			case slices.Contains(stdlibOnly, fromUnit) && (local || strings.Contains(strings.Split(imp, "/")[0], ".")):
				t.Errorf("%s imports %s: it may import only the standard library", from, to)
			case !local:
			case strings.HasPrefix(fromUnit, "apps/") && strings.HasPrefix(toUnit, "apps/") && fromUnit != toUnit:
				t.Errorf("%s imports %s: an app never imports another app", from, to)
			case !strings.HasPrefix(fromUnit, "apps/") && strings.HasPrefix(toUnit, "apps/"):
				t.Errorf("%s imports %s: internal/ and packages/ never import apps/", from, to)
			case fromUnit == "apps/ku" && toUnit != "internal/cli":
				t.Errorf("%s imports %s: the CLI talks to the server over HTTP and shares only internal/cli", from, to)
			case ruled && toUnit != fromUnit && !slices.Contains(rule, toUnit):
				t.Errorf("%s imports %s: layering goes downward only (%s may import %v)", from, to, fromUnit, rule)
			}
		}
	}
}
