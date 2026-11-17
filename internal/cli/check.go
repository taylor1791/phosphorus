package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/taylor1791/phosphorus/internal/audit"
	"github.com/taylor1791/phosphorus/internal/config"
)

func init() {
	Register(&Command{
		Name:    "check",
		Usage:   "[--strict] [--max-debt <duration>] [--unused]",
		Summary: "Validate graph, policy, and keys; the CI gate",
		Help: `check audits the whole repository without a key: the [env] reference graph,
declared versus stored secrets (every workspace environment counts), slots and
keys compared with trunk, reader coverage of referenced scopes, rotation debt,
and policy hygiene. It never loads an identity.

It exits 4 when there are errors, and 0 otherwise. Pending grants (policy
names a device that has no slot yet) and drops are reported without failing;
pending revocations and other warnings are reported too.

  --strict         also fail on warnings, pending grants and pending revocations
  --max-debt 14d   fail on rotation debt older than the limit (<n>d or <n>h)
  --unused         also list secrets that no [env] table references

With --json, stdout is {"ok", "counts", "findings", "rules"}.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Bool("strict", false, "fail on warnings, pending grants and pending revocations too")
			fs.String("max-debt", "", "fail on rotation debt older than this (`duration`, e.g. 14d)")
			fs.Bool("unused", false, "list secrets that no [env] table references")
		},
		Run: runCheck,
	})
}

type checkCounts struct {
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Info     int `json:"info"`
	Drops    int `json:"drops"`
}

type checkResult struct {
	OK       bool             `json:"ok"`
	Strict   bool             `json:"strict"`
	MaxDebt  string           `json:"max_debt,omitempty"`
	Counts   checkCounts      `json:"counts"`
	Findings []audit.Finding  `json:"findings"`
	Rules    []audit.RuleInfo `json:"rules"`
	report   *audit.Report
}

func runCheck(c *Context) error {
	var maxDebt time.Duration
	if s := c.String("max-debt"); s != "" {
		d, err := config.ParseDuration(s)
		if err != nil {
			return c.UsageErr("--max-debt: %v", err)
		}
		maxDebt = d
	}
	w, err := c.Workspace()
	if err != nil {
		return err
	}
	st, err := audit.Load(w.Repo)
	if err != nil {
		return err
	}
	rep := st.Check(audit.Options{Now: c.Now(), MaxDebt: maxDebt, Strict: c.Bool("strict"), Unused: c.Bool("unused")})
	res := checkResult{OK: !rep.Failed(), Strict: c.Bool("strict"), MaxDebt: c.String("max-debt"),
		Findings: rep.Findings, Rules: audit.Rules, report: rep}
	if res.Findings == nil {
		res.Findings = []audit.Finding{}
	}
	res.Counts = checkCounts{Errors: rep.Count(audit.Error), Warnings: rep.Count(audit.Warning), Info: rep.Count(audit.Info),
		Drops: len(rep.ByRule(audit.RuleDropPending)) + len(rep.ByRule(audit.RuleDropForbidden))}
	if err := c.Output(res, func(out io.Writer) { printCheck(out, res) }); err != nil {
		return err
	}
	if !res.OK {
		return &Error{Code: ExitCheckFailed, Message: fmt.Sprintf("check found %s", plural(res.Counts.Errors, "error")), silent: true}
	}
	return nil
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// printCheck prints drops first, in a banner, then findings grouped by
// severity and rule, then a one-line verdict.
func printCheck(out io.Writer, res checkResult) {
	var drops []audit.Finding
	for _, f := range res.Findings {
		if f.Rule == audit.RuleDropPending || f.Rule == audit.RuleDropForbidden {
			drops = append(drops, f)
		}
	}
	if len(drops) > 0 {
		bar := strings.Repeat("!", 72)
		fmt.Fprintln(out, bar)
		fmt.Fprintf(out, "!! %s TO REVIEW: values written to a scope's inbox, possibly by someone\n", strings.ToUpper(plural(len(drops), "drop")))
		fmt.Fprintln(out, "!! who cannot read it. Accept each one deliberately, like code.")
		fmt.Fprintln(out, "!!")
		rows := [][]string{}
		for _, f := range drops {
			set := ""
			if f.Set != nil {
				set = "set " + f.Set.Format("2006-01-02T15:04:05Z")
			}
			state := "DROP"
			if f.Rule == audit.RuleDropForbidden {
				state = "DROP (drops are off here: error)"
			}
			rows = append(rows, []string{"!!   " + f.Scope, f.Secret, set, state})
		}
		Table(out, rows)
		fmt.Fprintln(out, bar)
		fmt.Fprintln(out)
	}

	sections := []struct {
		sev   audit.Severity
		title string
	}{
		{audit.Error, "Errors"},
		{audit.Warning, "Warnings"},
		{audit.Info, "Notes"},
	}
	for _, sec := range sections {
		var fs []audit.Finding
		for _, f := range res.Findings {
			if f.Severity == sec.sev && f.Rule != audit.RuleDropPending {
				fs = append(fs, f)
			}
		}
		if len(fs) == 0 {
			continue
		}
		fmt.Fprintf(out, "%s (%d)\n\n", sec.title, len(fs))
		for i := 0; i < len(fs); {
			j := i
			for j < len(fs) && fs[j].Rule == fs[i].Rule {
				j++
			}
			if fs[i].Rule == audit.RuleSlotPendingGrant && j-i > 3 {
				printGrouped(out, fs[i:j])
			} else {
				for _, f := range fs[i:j] {
					printFinding(out, f)
				}
			}
			i = j
		}
	}

	var verdict string
	switch {
	case !res.OK:
		verdict = "check failed: "
	default:
		verdict = "check passed: "
	}
	parts := []string{plural(res.Counts.Errors, "error"), plural(res.Counts.Warnings, "warning")}
	if g := len(res.report.ByRule(audit.RuleSlotPendingGrant)); g > 0 {
		parts = append(parts, plural(g, "pending grant"))
	}
	if res.Counts.Drops > 0 {
		parts = append(parts, plural(res.Counts.Drops, "drop")+" to review")
	}
	if res.Strict {
		parts = append(parts, "--strict")
	}
	fmt.Fprintln(out, verdict+strings.Join(parts, ", ")+".")
}

func printFinding(out io.Writer, f audit.Finding) {
	where := f.Scope
	if where == "" {
		where = f.Package
	}
	if where == "" {
		where = f.File
	}
	label := string(f.Severity)
	if f.Strict {
		label += " (--strict)"
	}
	head := fmt.Sprintf("%s[%s]", label, f.Rule)
	if where != "" {
		head += " " + where
	}
	fmt.Fprintf(out, "%s: %s\n", head, f.Message)
	if f.Hint != "" {
		fmt.Fprintf(out, "    %s\n", f.Hint)
	}
	fmt.Fprintln(out)
}

// printGrouped prints many pending grants as one line per device.
func printGrouped(out io.Writer, fs []audit.Finding) {
	byDev := map[string][]string{}
	var order []string
	for _, f := range fs {
		if _, ok := byDev[f.Device]; !ok {
			order = append(order, f.Device)
		}
		byDev[f.Device] = append(byDev[f.Device], f.Scope)
	}
	label := string(fs[0].Severity)
	if fs[0].Strict {
		label += " (--strict)"
	}
	fmt.Fprintf(out, "%s[%s]: %s policy names, with no slot yet:\n", label, fs[0].Rule, plural(len(fs), "grant"))
	rows := [][]string{}
	for _, d := range order {
		rows = append(rows, []string{"    " + d, "-> " + plural(len(byDev[d]), "scope"), strings.Join(byDev[d], ", ")})
	}
	Table(out, rows)
	fmt.Fprintln(out, "    A reader of each scope runs `carbon apply`.")
	fmt.Fprintln(out)
}
