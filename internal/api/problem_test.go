package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

var kebab = regexp.MustCompile(`^[a-z]+(-[a-z]+)*$`)

// Every code is kebab-case with a sentence-case title (a capital, no final period), and Codes lists the table.
func TestProblemCodesAreWellFormed(t *testing.T) {
	codes := Codes()
	if len(codes) != len(problems) {
		t.Fatalf("Codes lists %d of %d", len(codes), len(problems))
	}
	for _, c := range codes {
		p := problems[c]
		if !kebab.MatchString(c) {
			t.Errorf("%q is not kebab-case", c)
		}
		if p.status < 400 || p.status > 599 {
			t.Errorf("%s: status %d", c, p.status)
		}
		if p.title == "" || !unicode.IsUpper([]rune(p.title)[0]) || strings.HasSuffix(p.title, ".") || p.title != strings.ToUpper(p.title[:1])+strings.ToLower(p.title[1:]) && !strings.HasPrefix(p.title, "HTTPS") {
			t.Errorf("%s: title %q is not sentence case", c, p.title)
		}
	}
}

// A domain error code that has no entry in domainCodes would reach the client as a 500 "internal".
func TestEveryDomainCodeIsMapped(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "../access/errors.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	ast.Inspect(f, func(x ast.Node) bool {
		spec, ok := x.(*ast.ValueSpec)
		if !ok || len(spec.Values) != 1 || !strings.HasPrefix(spec.Names[0].Name, "Code") {
			return true
		}
		n++
		code, _ := strconv.Unquote(spec.Values[0].(*ast.BasicLit).Value)
		if problem, ok := domainCodes[code]; !ok {
			t.Errorf("%s (%q) is not in domainCodes", spec.Names[0].Name, code)
		} else if _, ok := problems[problem]; !ok {
			t.Errorf("%s maps to %q, which is not in the problem table", spec.Names[0].Name, problem)
		}
		return true
	})
	if n == 0 {
		t.Fatal("found no domain codes: the test is looking in the wrong place")
	}
}
