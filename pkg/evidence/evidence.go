// Package evidence parses common CI/security report formats (JUnit, Snyk,
// Trivy, SARIF) into a normalized attestation payload with a deterministic
// compliance verdict, so Fides can ingest first-class evidence instead of only
// generic JSON (closing the gap with Kosli's built-in attestation types).
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
	Format     string         `json:"format"`
	Compliant  bool           `json:"compliant"`
	Summary    map[string]any `json:"summary"`
	Findings   []string       `json:"findings,omitempty"`
	Components []Component    `json:"components,omitempty"`
}

// SupportedFormats lists the formats Parse understands.
var SupportedFormats = []string{"junit", "snyk", "trivy", "sarif", "slsa", "sbom"}

// Parse dispatches to the format-specific parser.
func Parse(format string, data []byte) (Result, error) {
	switch strings.ToLower(format) {
	case "junit":
		return ParseJUnit(data)
	case "snyk":
		return ParseSnyk(data)
	case "trivy":
		return ParseTrivy(data)
	case "sarif":
		return ParseSARIF(data)
	case "slsa":
		return ParseSLSA(data)
	case "sbom":
		return ParseSBOM(data)
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

// ----- SARIF (Static Analysis Results Interchange Format) -----

type sarifReport struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
		} `json:"results"`
	} `json:"runs"`
}

// ParseSARIF summarizes a SARIF 2.1.0 report (runs[].results[] with level,
// ruleId and message.text), as emitted by CodeQL, Semgrep, Trivy, Grype and
// most SAST tools. Result levels are error/warning/note/none; a result with no
// level defaults to "warning" per the SARIF spec. Compliant when there are no
// error-level results; each error is reported as a finding.
func ParseSARIF(data []byte) (Result, error) {
	var r sarifReport
	if err := json.Unmarshal(data, &r); err != nil {
		return Result{}, fmt.Errorf("evidence: parse sarif: %w", err)
	}
	counts := map[string]int{"error": 0, "warning": 0, "note": 0, "none": 0}
	var findings []string
	total := 0
	for _, run := range r.Runs {
		for _, res := range run.Results {
			total++
			level := strings.ToLower(res.Level)
			if level == "" {
				level = "warning"
			}
			counts[level]++
			if level == "error" {
				rule := res.RuleID
				if rule == "" {
					rule = "(no rule id)"
				}
				if res.Message.Text != "" {
					findings = append(findings, fmt.Sprintf("ERROR: %s (%s)", rule, res.Message.Text))
				} else {
					findings = append(findings, fmt.Sprintf("ERROR: %s", rule))
				}
			}
		}
	}
	sort.Strings(findings)
	return Result{
		Format:    "sarif",
		Compliant: counts["error"] == 0,
		Summary: map[string]any{"total": total,
			"error": counts["error"], "warning": counts["warning"], "note": counts["note"], "none": counts["none"]},
		Findings: findings,
	}, nil
}

// ----- SBOM (CycloneDX / SPDX) -----

// Component is a normalized SBOM component (package/library), extracted from
// a CycloneDX or SPDX document and persisted alongside the artifact it was
// found in (see `fides attest sbom` / `fides search components`).
type Component struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	PURL     string   `json:"purl,omitempty"`
	Licenses []string `json:"licenses,omitempty"`
}

type cyclonedxDoc struct {
	BomFormat  string `json:"bomFormat"`
	Components []struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		PURL     string `json:"purl"`
		Licenses []struct {
			License struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"license"`
			Expression string `json:"expression"`
		} `json:"licenses"`
	} `json:"components"`
}

type spdxDoc struct {
	SPDXVersion string `json:"spdxVersion"`
	Packages    []struct {
		Name             string `json:"name"`
		VersionInfo      string `json:"versionInfo"`
		LicenseConcluded string `json:"licenseConcluded"`
		LicenseDeclared  string `json:"licenseDeclared"`
		ExternalRefs     []struct {
			ReferenceCategory string `json:"referenceCategory"`
			ReferenceType     string `json:"referenceType"`
			ReferenceLocator  string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
}

// ParseSBOM auto-detects CycloneDX vs SPDX JSON (via the "bomFormat" /
// "spdxVersion" discriminators) and normalizes the component list (name,
// version, purl, licenses). SBOM evidence is informational, so the result is
// always compliant; Summary reports the component count.
func ParseSBOM(data []byte) (Result, error) {
	var probe struct {
		BomFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return Result{}, fmt.Errorf("evidence: parse sbom: %w", err)
	}

	var components []Component
	var format string
	switch {
	case strings.EqualFold(probe.BomFormat, "CycloneDX"):
		format = "cyclonedx"
		var doc cyclonedxDoc
		if err := json.Unmarshal(data, &doc); err != nil {
			return Result{}, fmt.Errorf("evidence: parse cyclonedx sbom: %w", err)
		}
		for _, c := range doc.Components {
			var licenses []string
			for _, l := range c.Licenses {
				switch {
				case l.License.ID != "":
					licenses = append(licenses, l.License.ID)
				case l.License.Name != "":
					licenses = append(licenses, l.License.Name)
				case l.Expression != "":
					licenses = append(licenses, l.Expression)
				}
			}
			components = append(components, Component{Name: c.Name, Version: c.Version, PURL: c.PURL, Licenses: licenses})
		}
	case probe.SPDXVersion != "":
		format = "spdx"
		var doc spdxDoc
		if err := json.Unmarshal(data, &doc); err != nil {
			return Result{}, fmt.Errorf("evidence: parse spdx sbom: %w", err)
		}
		for _, p := range doc.Packages {
			var purl string
			for _, ref := range p.ExternalRefs {
				if strings.EqualFold(ref.ReferenceType, "purl") {
					purl = ref.ReferenceLocator
					break
				}
			}
			lic := p.LicenseConcluded
			if lic == "" || strings.EqualFold(lic, "NOASSERTION") {
				lic = p.LicenseDeclared
			}
			var licenses []string
			if lic != "" && !strings.EqualFold(lic, "NOASSERTION") && !strings.EqualFold(lic, "NONE") {
				licenses = append(licenses, lic)
			}
			components = append(components, Component{Name: p.Name, Version: p.VersionInfo, PURL: purl, Licenses: licenses})
		}
	default:
		return Result{}, fmt.Errorf("evidence: parse sbom: unrecognized format (expected CycloneDX \"bomFormat\" or SPDX \"spdxVersion\")")
	}

	sort.Slice(components, func(i, j int) bool {
		if components[i].Name != components[j].Name {
			return components[i].Name < components[j].Name
		}
		return components[i].Version < components[j].Version
	})

	return Result{
		Format:     format,
		Compliant:  true,
		Summary:    map[string]any{"components": len(components)},
		Components: components,
	}, nil
}

// ----- SLSA v1 provenance -----

// slsaPredicateType is the predicateType a compliant SLSA v1 in-toto
// provenance statement must declare.
const slsaPredicateType = "https://slsa.dev/provenance/v1"

// inTotoStatement is a minimal typed subset of an in-toto v1 Statement
// carrying a SLSA provenance predicate. Deliberately hand-rolled instead of
// pulling in-toto-golang/slsa-github-generator to keep this a small, focused
// dependency-free parser (matches the junit/snyk/trivy parsers above).
type inTotoStatement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Subject       []inTotoSubject `json:"subject"`
	Predicate     slsaPredicate   `json:"predicate"`
}

type inTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type slsaPredicate struct {
	BuildDefinition *slsaBuildDefinition `json:"buildDefinition"`
	RunDetails      *slsaRunDetails      `json:"runDetails"`
}

type slsaBuildDefinition struct {
	BuildType            string                   `json:"buildType"`
	ExternalParameters   map[string]any           `json:"externalParameters,omitempty"`
	InternalParameters   map[string]any           `json:"internalParameters,omitempty"`
	ResolvedDependencies []slsaResourceDescriptor `json:"resolvedDependencies,omitempty"`
}

type slsaRunDetails struct {
	Builder  *slsaBuilder  `json:"builder"`
	Metadata *slsaMetadata `json:"metadata,omitempty"`
}

type slsaBuilder struct {
	ID      string            `json:"id"`
	Version map[string]string `json:"version,omitempty"`
}

type slsaMetadata struct {
	InvocationID string `json:"invocationId,omitempty"`
	StartedOn    string `json:"startedOn,omitempty"`
	FinishedOn   string `json:"finishedOn,omitempty"`
}

type slsaResourceDescriptor struct {
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

// ParseSLSA parses a SLSA v1 in-toto provenance statement (predicateType
// https://slsa.dev/provenance/v1) and validates the fields required for the
// statement to be a usable attestation of how an artifact was built:
// predicateType, subject, predicate.buildDefinition (buildType) and
// predicate.runDetails.builder.id. Compliant only when every required field
// is present; otherwise each missing/mismatched field is reported as a
// finding.
func ParseSLSA(data []byte) (Result, error) {
	var stmt inTotoStatement
	if err := json.Unmarshal(data, &stmt); err != nil {
		return Result{}, fmt.Errorf("evidence: parse slsa: %w", err)
	}

	var findings []string
	if stmt.PredicateType != slsaPredicateType {
		findings = append(findings, fmt.Sprintf("unexpected predicateType %q (want %q)", stmt.PredicateType, slsaPredicateType))
	}
	if len(stmt.Subject) == 0 {
		findings = append(findings, "missing subject")
	}

	var buildType string
	if stmt.Predicate.BuildDefinition == nil {
		findings = append(findings, "missing predicate.buildDefinition")
	} else {
		buildType = stmt.Predicate.BuildDefinition.BuildType
		if buildType == "" {
			findings = append(findings, "missing predicate.buildDefinition.buildType")
		}
	}

	var builderID string
	if stmt.Predicate.RunDetails == nil {
		findings = append(findings, "missing predicate.runDetails")
	} else if stmt.Predicate.RunDetails.Builder == nil || stmt.Predicate.RunDetails.Builder.ID == "" {
		findings = append(findings, "missing predicate.runDetails.builder.id")
	} else {
		builderID = stmt.Predicate.RunDetails.Builder.ID
	}

	sort.Strings(findings)
	return Result{
		Format:    "slsa",
		Compliant: len(findings) == 0,
		Summary: map[string]any{
			"predicate_type": stmt.PredicateType,
			"builder_id":     builderID,
			"build_type":     buildType,
			"subjects":       len(stmt.Subject),
		},
		Findings: findings,
	}, nil
}
