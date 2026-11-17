package cli_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/clitest"
)

// TestRunOverhead measures goal 8 of the design: what `carbon run` adds,
// from process start to the exec of the command, for a package with 100
// secrets, read with a hybrid (ML-KEM-768 + X25519) identity, in trunk mode
// (so the keys are also checked against trunk).
//
// Three setups: a small repository (6 people, 1 package, 1 scope) and one
// closer to a real monorepo (30 people, 10 packages) where the package's
// [env] references only itself (1 scope) or 2 other packages too (3 scopes).
//
// It times `carbon run -- childhelper exit` and `childhelper exit` started
// directly, alternating, and reports the difference of the medians. It
// asserts nothing about the number, so a slow machine cannot make the suite
// flaky; run it with -v to see the result (docs/performance.md records it).
func TestRunOverhead(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test; skipped with -short")
	}
	for _, c := range []struct {
		name                   string
		people, packages, refs int
	}{
		{"small", 6, 1, 0},
		{"monorepo-1-scope", 30, 10, 0},
		{"monorepo-3-scopes", 30, 10, 2},
	} {
		t.Run(c.name, func(t *testing.T) { measureRun(t, c.people, c.packages, c.refs) })
	}
}

func measureRun(t *testing.T, people, packages, refs int) {
	helper := childHelper(t)
	r := clitest.NewWorkspace(t)
	ada := r.Person("ada")
	ada.Join()
	for i := 1; i < people; i++ {
		r.Person(fmt.Sprintf("p%02d", i)).Join()
	}
	const n = 100
	var body strings.Builder
	body.WriteString("[secrets]\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&body, "s%03d = { description = \"secret %d\" }\n", i, i)
	}
	body.WriteString("\n[env]\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&body, "S%03d = \"${s%03d}\"\n", i, i)
	}
	for j := 0; j < refs; j++ {
		fmt.Fprintf(&body, "REF%d_A = \"${other%d.a}\"\nREF%d_B = \"${other%d.b}\"\n", j, j, j, j)
	}
	r.AddPackage("services/perf", "perf", body.String())
	for j := 0; j < packages-1; j++ {
		r.AddPackage(fmt.Sprintf("services/other%d", j), fmt.Sprintf("other%d", j),
			"[secrets]\na = { description = \"a\" }\nb = { description = \"b\" }\n")
	}
	r.Commit("packages")
	for i := 0; i < n; i++ {
		ada.In("services/perf").Stdin(fmt.Sprintf("value-%03d-%s", i, strings.Repeat("x", 40))).
			Must("set", fmt.Sprintf("s%03d", i))
	}
	for j := 0; j < refs; j++ {
		for _, s := range []string{"a", "b"} {
			ada.In(fmt.Sprintf("services/other%d", j)).Stdin(fmt.Sprintf("value-ref-%d-%s", j, s)).Must("set", s)
		}
	}
	r.Commit("secrets")
	// Trunk mode, as in a real clone: run also checks each key against trunk.
	r.SetTrunk("main")
	if !strings.Contains(r.Read(".carbon/people/ada.toml"), "age1pq1") {
		t.Fatal("ada's identity is not hybrid")
	}

	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + ada.Home,
		"XDG_CONFIG_HOME=" + filepath.Join(ada.Home, ".config"),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"LC_ALL=C", "TZ=UTC",
	}
	dir := r.Path("services/perf")
	time1 := func(args ...string) time.Duration {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir, cmd.Env = dir, env
		start := time.Now()
		out, err := cmd.CombinedOutput()
		d := time.Since(start)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return d
	}
	carbon := []string{clitest.Binary(t), "run", "--", helper, "exit"}
	direct := []string{helper, "exit"}
	// Check the command really gets every value.
	cmd := exec.Command(clitest.Binary(t), "run", "--", helper, "env")
	cmd.Dir, cmd.Env = dir, env
	out, err := cmd.Output()
	if want := n + 2*refs; err != nil || strings.Count(string(out), "value-") != want {
		t.Fatalf("run did not pass %d values: %v", want, err)
	}

	for i := 0; i < 3; i++ { // warm caches
		time1(carbon...)
		time1(direct...)
	}
	const rounds = 40
	var withCarbon, without []time.Duration
	for i := 0; i < rounds; i++ {
		withCarbon = append(withCarbon, time1(carbon...))
		without = append(without, time1(direct...))
	}
	med := func(ds []time.Duration) time.Duration {
		s := append([]time.Duration(nil), ds...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		return s[len(s)/2]
	}
	p90 := func(ds []time.Duration) time.Duration {
		s := append([]time.Duration(nil), ds...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		return s[len(s)*9/10]
	}
	overhead := med(withCarbon) - med(without)
	t.Logf("%d people, %d packages, %d scopes opened, %d values, hybrid identity, trunk mode, %d rounds",
		people, packages, 1+refs, n+2*refs, rounds)
	t.Logf("  carbon run -- cmd: median %v, p90 %v", med(withCarbon).Round(10*time.Microsecond), p90(withCarbon).Round(10*time.Microsecond))
	t.Logf("  cmd directly:      median %v, p90 %v", med(without).Round(10*time.Microsecond), p90(without).Round(10*time.Microsecond))
	t.Logf("  overhead (difference of medians): %v (goal: under 50ms)", overhead.Round(10*time.Microsecond))
}
