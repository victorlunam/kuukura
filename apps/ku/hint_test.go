package main

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

// The hint under an ambiguity error is only worth printing if following it solves the problem and does no harm.
// TestAmbiguityHintResolves runs every selector of a few tags (and one exclusion) against several sets of secrets,
// in a linked and in an unlinked folder, and for each ambiguity it executes what the hint says. For every row:
//
//	it picks      the tags next to the row leave exactly that row, among the secrets of that name;
//	it is honest  "also leaves out X" is exactly the names that stop matching once those tags are added.
//
// and for the example line:
//
//	it keeps      every tag that was typed;
//	it never widens  it selects nothing that the typed selector did not;
//	it is careful it leaves nothing out whenever some row's tags leave nothing out;
//	it converges  following the example again and again ends in a run that works.
//
// Each scenario also says what it must show (several tags in a suggestion, a suggestion that leaves something
// out), so the test cannot pass by never reaching the cases it exists for.
type hintSecret struct {
	name string
	tags []string
}

type hintScenario struct {
	name      string
	secs      []hintSecret
	multiTag  bool // some suggestion needs more than one tag
	leavesOut bool // some suggestion has to leave another secret out of the run
}

var hintScenarios = []hintScenario{
	{name: "api and worker share names", secs: []hintSecret{
		{"DB_PASSWORD", []string{"app:shop", "env:dev"}},
		{"DB_PASSWORD", []string{"app:shop", "env:dev", "role:cf-worker"}},
		{"DB_USERNAME", []string{"app:shop", "env:dev"}},
		{"DB_USERNAME", []string{"app:shop", "env:dev", "role:cf-worker"}},
	}},
	{name: "env split plus a single secret", leavesOut: true, secs: []hintSecret{
		{"BASE_URL", []string{"app:shop", "env:dev"}},
		{"BASE_URL", []string{"app:shop", "env:prod"}},
		{"API_KEY", []string{"app:shop", "env:dev"}},
	}},
	// the first row's tag (env:dev) would drop API_KEY, the second one's (env:prod) keeps it: the example must use the second
	{name: "the first suggestion is the one that leaves a secret out", leavesOut: true, secs: []hintSecret{
		{"BASE_URL", []string{"app:shop", "env:dev"}},
		{"BASE_URL", []string{"app:shop", "env:prod"}},
		{"API_KEY", []string{"app:shop", "env:prod"}},
	}},
	{name: "three variants and a shared one", multiTag: true, leavesOut: true, secs: []hintSecret{
		{"X_KEY", []string{"app:shop"}},
		{"X_KEY", []string{"app:shop", "role:w"}},
		{"X_KEY", []string{"app:shop", "role:w", "team:t"}},
		{"Y_KEY", []string{"app:shop"}},
	}},
	{name: "no single tag picks the last", multiTag: true, secs: []hintSecret{
		{"X_KEY", []string{"app:shop", "p:1", "q:1"}},
		{"X_KEY", []string{"app:shop", "p:1", "r:1"}},
		{"X_KEY", []string{"app:shop", "q:1", "r:1"}},
		{"X_KEY", []string{"app:shop", "p:1", "q:1", "r:1"}},
	}},
	// what it is for: an example that dropped app:shop would select env:dev of shop2 too (the "never widens" check)
	{name: "two apps", secs: []hintSecret{
		{"BASE_URL", []string{"app:shop", "env:dev"}},
		{"BASE_URL", []string{"app:shop2", "env:dev"}},
		{"BASE_URL", []string{"app:shop", "env:prod"}},
	}},
	{name: "shared secret next to roles", multiTag: true, leavesOut: true, secs: []hintSecret{
		{"SENTRY_DSN", []string{"app:shop", "env:dev"}},
		{"DB_URL", []string{"app:shop", "env:dev", "role:api"}},
		{"DB_URL", []string{"app:shop", "env:dev", "role:worker"}},
		{"DB_URL", []string{"app:shop", "env:dev"}},
	}},
}

// secKey identifies a secret: its name and its tags in order.
func secKey(name string, tags []string) string {
	t := slices.Clone(tags)
	slices.Sort(t)
	return name + "|" + strings.Join(t, " ")
}

// hintLab is a running server with one scenario's secrets in it, seen from a linked or an unlinked folder.
type hintLab struct {
	w      *world
	env    map[string]string // nil: a folder linked to nothing; with CWD: linked to app:shop
	script string            // prints NAME=value for every name of the scenario
	value  map[string]string // secKey -> the value it was saved with
}

// run is `ku run <sel> -- <script>`: the exit code, what each name was set to, and the error text.
func (l hintLab) run(sel []string) (code int, vals map[string]string, errOut string) {
	r := l.w.ku("", false, l.env, append(append([]string{"run"}, sel...), "--", "sh", "-c", l.script)...)
	vals = map[string]string{}
	for _, line := range strings.Split(r.out, "\n") {
		if n, v, ok := strings.Cut(line, "="); ok && v != "" {
			vals[n] = v
		}
	}
	return r.code, vals, r.errOut
}

// rows is what `ku secret list <sel>` shows, as secKeys. The same selector, the same folder: so what run selects.
func (l hintLab) rows(sel []string) map[string]bool {
	out := map[string]bool{}
	lines := strings.Split(l.w.ku("", false, l.env, append([]string{"secret", "list"}, sel...)...).out, "\n")
	for _, line := range lines[min(1, len(lines)):] { // the first line is the header
		if f := strings.Fields(line); len(f) >= 3 {
			out[secKey(f[0], f[2:])] = true
		}
	}
	return out
}

// names is the sorted names of a set of rows.
func names(rows map[string]bool) []string {
	var out []string
	for k := range rows {
		if n, _, _ := strings.Cut(k, "|"); !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// without is what is in all and not in kept.
func without(all, kept []string) []string {
	var out []string
	for _, n := range all {
		if !slices.Contains(kept, n) {
			out = append(out, n)
		}
	}
	return out
}

type hintRow struct {
	name string
	tags []string
	pick string   // the tags to add, as printed (space separated)
	lost []string // the other secrets the hint says they would leave out
}

type hintReport struct {
	group   string
	rows    []hintRow
	example string
}

var hintRowRE = regexp.MustCompile(`^    (\S+)  (.*?)(?:  add (.+?) to pick this one(?: \(also leaves out ([^)]+)\))?)?$`)

// parseHint reads an ambiguity error. ok is false for any other text.
func parseHint(errOut string) (rep hintReport, ok bool) {
	for _, line := range strings.Split(errOut, "\n") {
		switch {
		case strings.Contains(line, " secrets are called ") || strings.HasSuffix(line, " secrets match:"):
			ok = true
		case strings.HasPrefix(line, "  For example: "):
			rep.example = strings.TrimPrefix(line, "  For example: ")
		default:
			if m := hintRowRE.FindStringSubmatch(line); m != nil {
				r := hintRow{name: m[1], tags: strings.Fields(m[2]), pick: m[3]}
				if m[4] != "" {
					r.lost = strings.Split(m[4], ", ")
				}
				rep.rows = append(rep.rows, r)
			}
		}
	}
	if len(rep.rows) > 0 {
		rep.group = rep.rows[0].name
	}
	return rep, ok
}

// exampleSelector is the selector of an example `ku run <selector> -- <command>`.
func exampleSelector(example string) ([]string, bool) {
	f := strings.Fields(example)
	if len(f) < 4 || f[0] != "ku" || f[1] != "run" || f[len(f)-2] != "--" || f[len(f)-1] != "<command>" {
		return nil, false
	}
	return f[2 : len(f)-2], true
}

// withName puts name first when the selector has none, so that only that name is looked at.
func withName(sel []string, name string) []string {
	if len(sel) > 0 && !strings.Contains(sel[0], ":") && !strings.HasPrefix(sel[0], notMark) {
		return slices.Clone(sel)
	}
	return append([]string{name}, sel...)
}

type hintStats struct {
	cases, picks, multiPicks, announcedLosses, examples, followed, steps int
}

func TestAmbiguityHintResolves(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a few thousand commands against a real server")
	}
	for _, sc := range hintScenarios {
		t.Run(sc.name, func(t *testing.T) {
			storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) { checkHintScenario(t, p, sc) })
		})
	}
}

func checkHintScenario(t *testing.T, p storage.Provider, sc hintScenario) {
	w, admin := userWorld(t, p)
	w.grant(admin, "dev@example.test", "write", "app:shop2")
	lab := hintLab{w: w, value: map[string]string{}}
	var secretNames, tagList []string
	for i, s := range sc.secs {
		v := fmt.Sprintf("val-%d", i)
		lab.value[secKey(s.name, s.tags)] = v
		mustOK(t, w.ku(v+"\n", false, nil, append([]string{"secret", "set", s.name}, append(slices.Clone(s.tags), "--yes")...)...))
		if !slices.Contains(secretNames, s.name) {
			secretNames = append(secretNames, s.name)
			lab.script += fmt.Sprintf("echo %s=$%s;", s.name, s.name)
		}
		for _, tg := range s.tags {
			if !slices.Contains(tagList, tg) {
				tagList = append(tagList, tg)
			}
		}
	}
	slices.Sort(tagList)
	dir := t.TempDir()
	mustOK(t, w.ku("", false, map[string]string{"CWD": dir}, "link", "shop"))

	var st hintStats
	failures := 0
	for _, linked := range []bool{false, true} {
		lab.env = nil
		if linked {
			lab.env = map[string]string{"CWD": dir}
		}
		for _, typed := range hintSelectors(tagList, secretNames) {
			bad := func(format string, args ...any) {
				t.Helper()
				t.Errorf("[linked=%v] ku run %s\n\t%s", linked, strings.Join(typed, " "), fmt.Sprintf(format, args...))
				if failures++; failures >= 12 {
					t.Fatal("too many failures, stopping")
				}
			}
			code, _, errOut := lab.run(typed)
			if code == 0 {
				continue
			}
			rep, ambiguous := parseHint(errOut)
			if !ambiguous {
				// the only other ways a selector fails here are by being empty or by not being a selector at all
				if !strings.Contains(errOut, "No matching secret") && !strings.Contains(errOut, "not linked to an app") &&
					!strings.Contains(errOut, "cannot be both required and excluded") && !strings.Contains(errOut, "A name or a tag is required") {
					bad("unexpected failure:\n%s", errOut)
				}
				continue
			}
			st.cases++
			checkAmbiguity(lab, typed, rep, errOut, bad, &st)
		}
	}
	t.Logf("%+v", st)
	if st.cases == 0 {
		t.Error("no selector was ambiguous: the test checked nothing")
	}
	if sc.multiTag && st.multiPicks == 0 {
		t.Error("the scenario should need a suggestion of several tags and none did")
	}
	if sc.leavesOut && st.announcedLosses == 0 {
		t.Error("the scenario should need a suggestion that leaves a secret out and none did")
	}
}

func checkAmbiguity(lab hintLab, typed []string, rep hintReport, errOut string, bad func(string, ...any), st *hintStats) {
	if len(rep.rows) < 2 {
		bad("an ambiguity lists %d secrets:\n%s", len(rep.rows), errOut)
		return
	}
	matched := lab.rows(typed)
	before := names(matched)

	// every row: its tags pick it, and what it says it leaves out is what it leaves out
	cleanRow := false
	for _, r := range rep.rows {
		if r.name != rep.group {
			bad("rows of different names in one ambiguity:\n%s", errOut)
		}
		if r.pick == "" {
			bad("no tags suggested for %v (two secrets of one name always differ in some tag):\n%s", r.tags, errOut)
			continue
		}
		st.picks++
		if len(strings.Fields(r.pick)) > 1 {
			st.multiPicks++
		}
		picked := append(withName(typed, r.name), strings.Fields(r.pick)...)
		if got := lab.rows(picked); len(got) != 1 || !got[secKey(r.name, r.tags)] {
			bad("add %s to pick %v, and that selects %v:\n%s", r.pick, r.tags, got, errOut)
		}
		code, vals, e := lab.run(picked)
		if code != 0 || vals[r.name] != lab.value[secKey(r.name, r.tags)] {
			bad("add %s to pick %v, and running it gives code %d, %q:\n%s", r.pick, r.tags, code, vals[r.name], e)
		}
		lost := without(before, names(lab.rows(append(slices.Clone(typed), strings.Fields(r.pick)...))))
		if !slices.Equal(lost, r.lost) && (len(lost) > 0 || len(r.lost) > 0) {
			bad("add %s says it leaves out %v, and it leaves out %v:\n%s", r.pick, r.lost, lost, errOut)
		}
		if len(r.lost) > 0 {
			st.announcedLosses++
		} else {
			cleanRow = true
		}
	}

	// the example
	sel, ok := exampleSelector(rep.example)
	if !ok {
		bad("the example is not `ku run <selector> -- <command>`: %q\n%s", rep.example, errOut)
		return
	}
	st.examples++
	for _, tok := range typed {
		if !slices.Contains(sel, tok) {
			bad("the example drops %q: %s", tok, rep.example)
		}
	}
	chosen := lab.rows(sel)
	for k := range chosen {
		if !matched[k] {
			bad("the example selects %q, which the typed selector did not: %s", k, rep.example)
		}
	}
	if lost := without(before, names(chosen)); cleanRow && len(lost) > 0 {
		bad("the example leaves out %v although a suggestion that leaves nothing out exists:\n%s", lost, errOut)
	}

	// following it, again and again, ends in a run that works
	for step := 1; ; step++ {
		if step > len(before)+1 {
			bad("still failing after %d examples, now ku run %s", step-1, strings.Join(sel, " "))
			return
		}
		code, _, e := lab.run(sel)
		if code == 0 {
			st.followed++
			st.steps = max(st.steps, step)
			return
		}
		next, isHint := parseHint(e)
		if !isHint {
			bad("after the example, ku run %s fails with something else:\n%s", strings.Join(sel, " "), e)
			return
		}
		if sel, ok = exampleSelector(next.example); !ok {
			bad("ku run %s is ambiguous and gives no example:\n%s", strings.Join(sel, " "), e)
			return
		}
	}
}

// hintSelectors is every selector of up to two required tags (of different keys) and up to one excluded tag, with
// and without a name.
func hintSelectors(tags, secretNames []string) [][]string {
	key := func(s string) string { k, _, _ := strings.Cut(s, ":"); return k }
	required := [][]string{nil}
	for i, a := range tags {
		required = append(required, []string{a})
		for _, b := range tags[i+1:] {
			if key(a) != key(b) {
				required = append(required, []string{a, b})
			}
		}
	}
	var out [][]string
	for _, name := range append([]string{""}, secretNames...) {
		for _, req := range required {
			excluded := [][]string{nil}
			for _, tg := range tags {
				if !slices.Contains(req, tg) {
					excluded = append(excluded, []string{notMark + tg})
				}
			}
			for _, ex := range excluded {
				sel := slices.Concat(req, ex)
				if name != "" {
					sel = slices.Concat([]string{name}, sel)
				}
				if len(sel) > 0 {
					out = append(out, sel)
				}
			}
		}
	}
	return out
}

// scenario is the secrets of the scenario with that name.
func scenario(t *testing.T, name string) []hintSecret {
	t.Helper()
	for _, sc := range hintScenarios {
		if sc.name == name {
			return sc.secs
		}
	}
	t.Fatalf("no scenario %q", name)
	return nil
}

// The wording and the alignment are part of the help the hint gives, so a few errors are checked whole.
func TestAmbiguityHintText(t *testing.T) {
	apiAndWorker := scenario(t, "api and worker share names")[:2] // DB_PASSWORD, with and without the worker's role
	for _, c := range []struct {
		name string
		secs []hintSecret
		args []string
		want string
	}{
		{"api and worker", apiAndWorker, []string{"run", "app:shop", "env:dev", "--", "true"},
			"✗ 2 secrets are called DB_PASSWORD:\n" +
				"    DB_PASSWORD  app:shop env:dev                 add ~role:cf-worker to pick this one\n" +
				"    DB_PASSWORD  app:shop env:dev role:cf-worker  add role:cf-worker to pick this one\n" +
				"  For example: ku run app:shop env:dev ~role:cf-worker -- <command>\n"},
		{"shared secret next to roles", scenario(t, "shared secret next to roles"), []string{"run", "app:shop", "--", "true"},
			"✗ 3 secrets are called DB_URL:\n" +
				"    DB_URL  app:shop env:dev              add ~role:api ~role:worker to pick this one\n" +
				"    DB_URL  app:shop env:dev role:api     add role:api to pick this one (also leaves out SENTRY_DSN)\n" +
				"    DB_URL  app:shop env:dev role:worker  add role:worker to pick this one (also leaves out SENTRY_DSN)\n" +
				"  For example: ku run app:shop ~role:api ~role:worker -- <command>\n"},
		{"secret get keeps the flag", apiAndWorker, []string{"secret", "get", "DB_PASSWORD", "app:shop", "--out", "/tmp/x"},
			"✗ 2 secrets are called DB_PASSWORD:\n" +
				"    DB_PASSWORD  app:shop env:dev                 add ~role:cf-worker to pick this one\n" +
				"    DB_PASSWORD  app:shop env:dev role:cf-worker  add role:cf-worker to pick this one\n" +
				"  For example: ku secret get DB_PASSWORD app:shop ~role:cf-worker --out <path>\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
				w, _ := userWorld(t, p)
				for i, s := range c.secs {
					mustOK(t, w.ku(fmt.Sprintf("v%d\n", i), false, nil, append([]string{"secret", "set", s.name}, append(slices.Clone(s.tags), "--yes")...)...))
				}
				before := w.stepUps
				r := w.ku("", false, nil, c.args...)
				if r.code != 1 || !strings.HasSuffix(r.errOut, c.want) {
					t.Fatalf("code %d, got:\n%s\nwant it to end with:\n%s", r.code, r.errOut, c.want)
				}
				if w.stepUps != before {
					t.Fatal("an ambiguity must be reported before any confirmation is asked")
				}
			})
		})
	}
}
