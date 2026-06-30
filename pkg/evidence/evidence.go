// Package evidence parses common CI/security report formats (JUnit, Snyk,
// Trivy) into a normalized attestation payload with a deterministic compliance
// verdict, so Fides can ingest first-class evidence instead of only generic
// JSON (closing the gap with Kosli's built-in attestation types).
package evidence

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

// Result is the normalized payload recorded as an attestation. The Summary
// fields are jq-evaluable (e.g. `.summary.failed == 0`).
type Result struct {
	Format    string         `json:"format"`
	Compliant bool           `json:"compliant"`
	Summary   map[string]any `json:"summary"`
	Findings  []string       `json:"findings,omitempty"`
}

// SupportedFormats lists the formats Parse understands.
var SupportedFormats = []string{"junit", "snyk", "trivy"}

// Parse dispatches to the format-specific parser.
func Parse(format string, data []byte) (Result, error) {
	switch strings.ToLower(format) {
	case "junit":
		return ParseJUnit(data)
	case "snyk":
		return ParseSnyk(data)
	case "trivy":
		return ParseTrivy(data)
	default:
		return Result{}, fmt.Errorf("unsupported evidence format %q (supported: %s)", format, strings.Join(SupportedFormats, ", "))
	}
}

// ----- JUnit -----

type junitSuites struct {
	XMLName xml.Name     `xml:"testsuites"`
	Suites  []junitSuite `xml:"testsuite"`
}
type junitSuite struct {
	XMLName xml.Name    `xml:"testsuite"`
	Cases   []junitCase `xml:"testcase"`
}
type junitCase struct {
	Name      string    `xml:"name,attr"`
	ClassName string    `xml:"classname,attr"`
	Failure   *struct{} `xml:"failure"`
	Error     *struct{} `xml:"error"`
	Skipped   *struct{} `xml:"skipped"`
}

// ParseJUnit counts test outcomes from a JUnit XML report (handles both a
// <testsuites> root and a single <testsuite>). Compliant when no failures/errors.
func ParseJUnit(data []byte) (Result, error) {
	var suites junitSuites
	cases := []junitCase{}
	if err := xml.Unmarshal(data, &suites); err == nil && len(suites.Suites) > 0 {
		for _, s := range suites.Suites {
			cases = append(cases, s.Cases...)
		}
	} else {
		var single junitSuite
		if err := xml.Unmarshal(data, &single); err != nil {
			return Result{}, fmt.Errorf("evidence: parse junit: %w", err)
		}
		cases = single.Cases
	}

	var failed, errored, skipped int
	var findings []string
	for _, c := range cases {
		switch {
		case c.Failure != nil:
			failed++
			findings = append(findings, testName(c))
		case c.Error != nil:
			errored++
			findings = append(findings, testName(c))
		case c.Skipped != nil:
			skipped++
		}
	}
	total := len(cases)
	passed := total - failed - errored - skipped
	sort.Strings(findings)
	return Result{
		Format:    "junit",
		Compliant: failed == 0 && errored == 0,
		Summary:   map[string]any{"total": total, "passed": passed, "failed": failed, "errors": errored, "skipped": skipped},
		Findings:  findings,
	}, nil
}

func testName(c junitCase) string {
	if c.ClassName != "" {
		return c.ClassName + "." + c.Name
	}
	return c.Name
}

// ----- Snyk -----

type snykReport struct {
	OK              bool `json:"ok"`
	Vulnerabilities []struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
	} `json:"vulnerabilities"`
}

// ParseSnyk summarizes a `snyk test --json` report. Compliant when there are no
// critical or high vulnerabilities.
func ParseSnyk(data []byte) (Result, error) {
	var r snykReport
	if err := json.Unmarshal(data, &r); err != nil {
		return Result{}, fmt.Errorf("evidence: parse snyk: %w", err)
	}
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	var findings []string
	for _, v := range r.Vulnerabilities {
		sev := strings.ToLower(v.Severity)
		counts[sev]++
		if sev == "critical" || sev == "high" {
			findings = append(findings, fmt.Sprintf("%s: %s (%s)", strings.ToUpper(sev), v.Title, v.ID))
		}
	}
	sort.Strings(findings)
	return Result{
		Format:    "snyk",
		Compliant: counts["critical"] == 0 && counts["high"] == 0,
		Summary: map[string]any{"total": len(r.Vulnerabilities),
			"critical": counts["critical"], "high": counts["high"], "medium": counts["medium"], "low": counts["low"]},
		Findings: findings,
	}, nil
}

// ----- Trivy -----

type trivyReport struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			Severity        string `json:"Severity"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// ParseTrivy summarizes a `trivy ... -f json` report. Compliant when there are
// no CRITICAL or HIGH vulnerabilities.
func ParseTrivy(data []byte) (Result, error) {
	var r trivyReport
	if err := json.Unmarshal(data, &r); err != nil {
		return Result{}, fmt.Errorf("evidence: parse trivy: %w", err)
	}
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	var findings []string
	total := 0
	for _, res := range r.Results {
		for _, v := range res.Vulnerabilities {
			total++
			sev := strings.ToLower(v.Severity)
			counts[sev]++
			if sev == "critical" || sev == "high" {
				findings = append(findings, fmt.Sprintf("%s: %s", strings.ToUpper(sev), v.VulnerabilityID))
			}
		}
	}
	sort.Strings(findings)
	return Result{
		Format:    "trivy",
		Compliant: counts["critical"] == 0 && counts["high"] == 0,
		Summary: map[string]any{"total": total,
			"critical": counts["critical"], "high": counts["high"], "medium": counts["medium"], "low": counts["low"]},
		Findings: findings,
	}, nil
}
