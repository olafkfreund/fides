package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"

	"fides/pkg/evidence"
	"fides/pkg/exitcode"
)

// cliCVERe matches CVE identifiers anywhere in a finding string.
var cliCVERe = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// handleVuln is the `fides vuln <subcommand>` entrypoint.
func handleVuln(_ CLIConfig, args []string) {
	if len(args) >= 1 && args[0] == "diff" {
		handleVulnDiff(args[1:])
		return
	}
	fmt.Println("Usage: fides vuln diff <baseline> <current> [--format trivy|snyk|sarif] [--fail-on-new]")
	os.Exit(1)
}

// handleVulnDiff compares two vulnerability-scan reports and reports the CVEs
// introduced (in current but not baseline) vs fixed — the "did this change add a
// vulnerability?" gate. With --fail-on-new it exits 2 (a policy violation) when
// any new CVE appears, so CI can block only on *introduced* risk, not the
// pre-existing backlog. Offline; no server round-trip.
//
// ponytail: CVEs come from evidence.Parse's Findings, which for trivy/snyk cover
// CRITICAL+HIGH only — i.e. this gates on new high/critical CVEs. Widen the
// parser's findings if medium/low deltas ever matter.
func handleVulnDiff(args []string) {
	format := "trivy"
	failOnNew := false
	var files []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--fail-on-new":
			failOnNew = true
		case "--format":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		default:
			files = append(files, args[i])
		}
	}
	if len(files) != 2 {
		fmt.Println("Usage: fides vuln diff <baseline> <current> [--format trivy|snyk|sarif] [--fail-on-new]")
		os.Exit(1)
	}

	added, fixed := diffCVEs(cvesFromReport(format, files[0]), cvesFromReport(format, files[1]))

	fmt.Printf("Vuln diff (%s): %s -> %s\n", format, files[0], files[1])
	fmt.Printf("  +%d new  -%d fixed\n\n", len(added), len(fixed))
	for _, c := range added {
		fmt.Printf("  + %s (new)\n", c)
	}
	for _, c := range fixed {
		fmt.Printf("  - %s (fixed)\n", c)
	}
	if len(added)+len(fixed) == 0 {
		fmt.Println("  no change in CVE set")
	}

	if failOnNew && len(added) > 0 {
		fmt.Printf("\n%d new vulnerability(ies) introduced — gate failed.\n", len(added))
		os.Exit(exitcode.Violation)
	}
}

func cvesFromReport(format, path string) map[string]bool {
	data, err := os.ReadFile(path) // #nosec G304 G703 -- CLI reads a user-specified report by design
	fail(err, "read "+path)
	r, err := evidence.Parse(format, data)
	fail(err, "parse "+path)
	set := map[string]bool{}
	for _, f := range r.Findings {
		for _, m := range cliCVERe.FindAllString(f, -1) {
			set[m] = true
		}
	}
	return set
}

// diffCVEs returns the sorted CVEs added (in cur, not base) and fixed (in base,
// not cur).
func diffCVEs(base, cur map[string]bool) (added, fixed []string) {
	for c := range cur {
		if !base[c] {
			added = append(added, c)
		}
	}
	for c := range base {
		if !cur[c] {
			fixed = append(fixed, c)
		}
	}
	sort.Strings(added)
	sort.Strings(fixed)
	return added, fixed
}
