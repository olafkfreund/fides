package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strconv"
	"strings"

	"fides/pkg/exitcode"
)

func handleAssert(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("assert", flag.ExitOnError)
	sha := cmd.String("sha256", "", "Artifact SHA256 digest")
	policyName := cmd.String("policy", "", "Unsupported policy selector (omit this flag)")

	cmd.Parse(args)

	if *policyName != "" {
		fmt.Println("Error: --policy is unsupported for assert. Use --sha256 to check artifact compliance.")
		os.Exit(exitcode.Error)
	}

	if *sha == "" {
		fmt.Println("Error: --sha256 is required")
		cmd.Usage()
		os.Exit(1)
	}

	q := neturl.Values{}
	q.Set("sha256", *sha)
	reqURL := fmt.Sprintf("%s/api/v1/compliance?%s", config.ServerURL, q.Encode())
	req, err := http.NewRequest("GET", reqURL, nil) // #nosec G704 -- request targets the operator-configured Fides server (FIDES_SERVER_URL)
	if err != nil {
		fmt.Printf("Failed to create request: %v\n", err)
		os.Exit(1)
	}

	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}

	resp, err := httpClient.Do(req) // #nosec G704 -- request targets the operator-configured Fides server (FIDES_SERVER_URL)
	if err != nil {
		fmt.Printf("Server check failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		fmt.Printf("Server check failed: HTTP %d\n", resp.StatusCode)
		os.Exit(exitcode.Error)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Failed to read response: %v\n", err)
		os.Exit(exitcode.Error)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Printf("Failed to parse response: %v\n", err)
		os.Exit(exitcode.Error)
	}

	compliant, ok := result["compliant"].(bool)
	if !ok {
		fmt.Println("Failed to parse response: expected a boolean compliant field")
		os.Exit(exitcode.Error)
	}
	violations, _ := result["violations"].([]interface{})

	if !compliant {
		fmt.Printf("COMPLIANCE FAILURE: Artifact %s is NON-COMPLIANT\n", *sha)
		for _, v := range violations {
			fmt.Printf("  - %v\n", v)
		}
		os.Exit(assertExit(false)) // Violation (2) — a completed gate that said no.
	}

	fmt.Printf("COMPLIANCE PASS: Artifact %s is compliant with policies\n", *sha)
}

// assertExit maps a compliance verdict to a process exit code: compliant -> OK,
// non-compliant -> Violation (2). This aligns `assert` with verify-image /
// change-gate so CI gates on exit 2 the same way for every gate command.
func assertExit(compliant bool) int {
	if compliant {
		return exitcode.OK
	}
	return exitcode.Violation
}

// fides change-gate --trail <id> — evidence-backed approval verdict + risk score.
func handleChangeGate(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("change-gate", flag.ExitOnError)
	trail := cmd.String("trail", "", "trail UUID")
	cmd.Parse(args)
	if *trail == "" {
		fmt.Println("Usage: fides change-gate --trail <id>")
		os.Exit(1)
	}
	body, err := getRequest(config, "/api/v1/trails/"+*trail+"/change-gate")
	fail(err, "evaluate change gate")
	fmt.Println(body)
	if strings.Contains(body, "\"approved\":false") {
		os.Exit(exitcode.Violation) // so CI / a change pipeline can gate on the verdict
	}
}

// fides control add|list|coverage|archive|unarchive
func handleControl(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides control <add|list|catalog|coverage|timeline|frameworks|import|enforce|archive|unarchive> [flags]")
		os.Exit(1)
	}
	switch args[0] {
	case "add":
		cmd := flag.NewFlagSet("control add", flag.ExitOnError)
		key := cmd.String("key", "", "control key, e.g. SOC2-CC6.1")
		name := cmd.String("name", "", "control name")
		desc := cmd.String("description", "", "description")
		framework := cmd.String("framework", "", "SOC2 | ISO27001 | FDA-21CFR11")
		require := cmd.String("require", "", "comma-separated attestation types (e.g. junit,trivy,sbom-cyclonedx,slsa-provenance,cosign-verification)")
		cmd.Parse(args[1:])
		if *key == "" || *name == "" {
			fmt.Println("Error: --key and --name are required")
			os.Exit(1)
		}
		var types []string
		if *require != "" {
			types = strings.Split(*require, ",")
		}
		post(config, "/api/v1/controls", map[string]any{"key": *key, "name": *name, "description": *desc, "framework": *framework, "required_types": types}, "Control saved")
	case "list":
		cmd := flag.NewFlagSet("control list", flag.ExitOnError)
		all := cmd.Bool("all", false, "include archived")
		cmd.Parse(args[1:])
		p := "/api/v1/controls"
		if *all {
			p += "?include_archived=true"
		}
		body, err := getList(config, p)
		fail(err, "list controls")
		fmt.Println(body)
	case "coverage":
		body, err := getRequest(config, "/api/v1/controls/coverage")
		fail(err, "controls coverage")
		fmt.Println(body)
	case "timeline":
		cmd := flag.NewFlagSet("control timeline", flag.ExitOnError)
		key := cmd.String("key", "", "scope to a single control key (optional)")
		days := cmd.Int("days", 90, "look-back window in days")
		cmd.Parse(args[1:])
		p := "/api/v1/controls/timeline?days=" + strconv.Itoa(*days)
		if *key != "" {
			p += "&key=" + neturl.QueryEscape(*key)
		}
		body, err := getRequest(config, p)
		fail(err, "control timeline")
		fmt.Println(body)
	case "frameworks":
		body, err := getList(config, "/api/v1/frameworks")
		fail(err, "list frameworks")
		fmt.Println(body)
	case "catalog":
		cmd := flag.NewFlagSet("control catalog", flag.ExitOnError)
		framework := cmd.String("framework", "", "filter by framework (e.g. SOC2, NIST-800-53)")
		area := cmd.String("area", "", "filter by area (build|release|runtime|change|lifecycle)")
		typ := cmd.String("type", "", "filter by type (preventive|detective)")
		cmd.Parse(args[1:])
		q := neturl.Values{}
		for k, v := range map[string]string{"framework": *framework, "area": *area, "type": *typ} {
			if v != "" {
				q.Set(k, v)
			}
		}
		p := "/api/v1/control-catalog"
		if len(q) > 0 {
			p += "?" + q.Encode()
		}
		body, err := getRequest(config, p)
		fail(err, "control catalog")
		fmt.Println(body)
	case "import":
		cmd := flag.NewFlagSet("control import", flag.ExitOnError)
		framework := cmd.String("framework", "", "framework name (SOC2, ISO27001, NIST-800-53, PCI-DSS, DORA, PSD2, SOX, SLSA, CRA)")
		cmd.Parse(args[1:])
		if *framework == "" {
			fmt.Println("Error: --framework is required (see: fides control frameworks)")
			os.Exit(1)
		}
		post(config, "/api/v1/controls/import-framework", map[string]any{"framework": *framework}, "Framework controls imported")
	case "enforce":
		cmd := flag.NewFlagSet("control enforce", flag.ExitOnError)
		key := cmd.String("key", "", "control key to enforce (omit when using --all-controls)")
		env := cmd.String("env", "", "environment UUID (omit when using --all-environments)")
		allEnvs := cmd.Bool("all-environments", false, "enforce across every environment")
		allControls := cmd.Bool("all-controls", false, "enforce every active control")
		cmd.Parse(args[1:])
		if *key == "" && !*allControls {
			fmt.Println("Error: --key or --all-controls is required")
			os.Exit(1)
		}
		if *env == "" && !*allEnvs {
			fmt.Println("Error: --env or --all-environments is required")
			os.Exit(1)
		}
		body := map[string]any{}
		if *allEnvs {
			body["all"] = true
		} else {
			body["environment_id"] = *env
		}
		keys := []string{}
		if *allControls {
			raw, err := getList(config, "/api/v1/controls")
			fail(err, "list controls")
			var ctrls []struct {
				Key string `json:"key"`
			}
			if err := json.Unmarshal([]byte(raw), &ctrls); err != nil {
				fail(err, "parse controls")
			}
			for _, c := range ctrls {
				keys = append(keys, c.Key)
			}
			if len(keys) == 0 {
				fmt.Println("No active controls to enforce — import a framework first (fides control import).")
				return
			}
		} else {
			keys = append(keys, *key)
		}
		for _, k := range keys {
			post(config, "/api/v1/controls/"+neturl.PathEscape(k)+"/enforce", body, "Enforced "+k)
		}
	case "archive", "unarchive":
		cmd := flag.NewFlagSet("control "+args[0], flag.ExitOnError)
		id := cmd.String("id", "", "control UUID")
		cmd.Parse(args[1:])
		if *id == "" {
			fmt.Println("Error: --id is required")
			os.Exit(1)
		}
		post(config, "/api/v1/controls/"+*id+"/"+args[0], map[string]any{}, "Done")
	default:
		fmt.Println("Usage: fides control <add|list|coverage|frameworks|import|enforce|archive|unarchive>")
		os.Exit(1)
	}
}

// fides policy add|list|check --env <id> ...
func handlePolicy(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides policy <create|delete|generate|add|list|check> [flags]")
		os.Exit(1)
	}
	// Global (org-level) policies: create / delete / AI-generate.
	switch args[0] {
	case "create":
		c := flag.NewFlagSet("policy create", flag.ExitOnError)
		name := c.String("name", "", "policy name")
		desc := c.String("description", "", "description")
		rulesFile := c.String("rules-file", "", "file with the policy rules (jq/JSON)")
		c.Parse(args[1:])
		if *name == "" {
			fmt.Println("Error: --name is required")
			os.Exit(1)
		}
		rules := ""
		if *rulesFile != "" {
			data, err := os.ReadFile(*rulesFile) // #nosec G304 G703 -- CLI reads a user-specified rules file by design
			fail(err, "read rules file")
			rules = string(data)
		}
		post(config, "/api/v1/policies/create", map[string]any{"name": *name, "description": *desc, "rules": rules}, "Policy created")
		return
	case "delete":
		c := flag.NewFlagSet("policy delete", flag.ExitOnError)
		id := c.String("id", "", "policy UUID")
		c.Parse(args[1:])
		if *id == "" {
			fmt.Println("Error: --id is required")
			os.Exit(1)
		}
		body, err := deleteRequest(config, "/api/v1/policies/"+*id)
		fail(err, "delete policy")
		fmt.Println(body)
		return
	case "generate":
		c := flag.NewFlagSet("policy generate", flag.ExitOnError)
		framework := c.String("framework", "SOC2", "compliance framework")
		desc := c.String("description", "", "what the policy should enforce")
		c.Parse(args[1:])
		if *desc == "" {
			fmt.Println("Error: --description is required")
			os.Exit(1)
		}
		body, err := postRequest(config, "/api/v1/ai/generate-policy", map[string]any{"framework": *framework, "description": *desc})
		fail(err, "generate policy")
		fmt.Println(body)
		return
	}
	cmd := flag.NewFlagSet("policy "+args[0], flag.ExitOnError)
	env := cmd.String("env", "", "environment UUID")
	name := cmd.String("name", "", "policy name")
	require := cmd.String("require", "", "comma-separated required attestation types (e.g. junit,trivy,sbom-cyclonedx,slsa-provenance,cosign-verification)")
	ifTag := cmd.String("if-tag", "", "only enforce when flow tag == value")
	ifValue := cmd.String("if-value", "", "tag value")
	trail := cmd.String("trail", "", "trail UUID (for check)")
	cmd.Parse(args[1:])
	if *env == "" {
		fmt.Println("Error: --env is required")
		os.Exit(1)
	}
	base := "/api/v1/environments/" + *env
	switch args[0] {
	case "add":
		if *name == "" || *require == "" {
			fmt.Println("Error: --name and --require are required")
			os.Exit(1)
		}
		post(config, base+"/policies", map[string]any{
			"name": *name, "required_types": strings.Split(*require, ","),
			"if_tag": *ifTag, "if_value": *ifValue,
		}, "Policy saved")
	case "list":
		body, err := getList(config, base+"/policies")
		fail(err, "list policies")
		fmt.Println(body)
	case "check":
		if *trail == "" {
			fmt.Println("Error: --trail is required for check")
			os.Exit(1)
		}
		body, err := getRequest(config, base+"/policy-check?trail="+*trail)
		fail(err, "policy check")
		fmt.Println(body)
		if strings.Contains(body, "\"compliant\":false") {
			os.Exit(exitcode.Violation) // so CI can gate a deploy
		}
	default:
		fmt.Println("Usage: fides policy <add|list|check> --env <id>")
		os.Exit(1)
	}
}

// fides approve --trail <id> [--reason r] [--role approver|deployer] — record a
// segregation-of-duties approval. Each approve call refreshes the trail's
// segregation-of-duties attestation (committer != approver != deployer).
func handleApprove(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("approve", flag.ExitOnError)
	trail := cmd.String("trail", "", "trail UUID")
	reason := cmd.String("reason", "", "approval reason")
	role := cmd.String("role", "approver", "segregation-of-duties role this approval represents: approver | deployer")
	cmd.Parse(args)
	if *trail == "" {
		fmt.Println("Usage: fides approve --trail <id> [--reason <r>] [--role approver|deployer]")
		os.Exit(1)
	}
	if *role != "approver" && *role != "deployer" {
		fmt.Println("Error: --role must be 'approver' or 'deployer'")
		os.Exit(1)
	}
	post(config, "/api/v1/trails/"+*trail+"/approvals", map[string]any{"reason": *reason, "role": *role}, "Approval recorded")
}

// handleTraining: fides training <record|list> — security-training audit evidence.
func handleTraining(config CLIConfig, args []string) {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "record":
		cmd := flag.NewFlagSet("training record", flag.ExitOnError)
		person := cmd.String("person", "", "who completed it (required)")
		course := cmd.String("course", "", "course/topic, e.g. owasp-top-10 (required)")
		date := cmd.String("date", "", "completion date, RFC3339 (default now)")
		notes := cmd.String("notes", "", "optional notes")
		cmd.Parse(args[1:])
		if *person == "" || *course == "" {
			fmt.Println("Usage: fides training record --person <who> --course <topic> [--date <RFC3339>] [--notes ...]")
			os.Exit(1)
		}
		post(config, "/api/v1/training", map[string]any{
			"person": *person, "course": *course, "completed_at": *date, "notes": *notes,
		}, "Training recorded")
	case "list":
		body, err := getList(config, "/api/v1/training")
		fail(err, "list training")
		fmt.Println(body)
	default:
		fmt.Println("Usage: fides training <record|list> ...")
		os.Exit(1)
	}
}

// handleService: fides service <set|list> — service ownership registry + tier.
func handleService(config CLIConfig, args []string) {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "set":
		cmd := flag.NewFlagSet("service set", flag.ExitOnError)
		name := cmd.String("name", "", "service name (required)")
		owner := cmd.String("owner", "", "owner")
		onCall := cmd.String("on-call", "", "on-call contact")
		audit := cmd.String("audit", "", "audit-responsible contact")
		tier := cmd.Int("tier", 1, "criticality tier 1..3 (scales which controls apply)")
		cmd.Parse(args[1:])
		if *name == "" {
			fmt.Println("Usage: fides service set --name <s> [--owner --on-call --audit] [--tier 1..3]")
			os.Exit(1)
		}
		post(config, "/api/v1/services", map[string]any{
			"service": *name, "owner": *owner, "on_call": *onCall, "audit_contact": *audit, "tier": *tier,
		}, "Service saved")
	case "list":
		body, err := getList(config, "/api/v1/services")
		fail(err, "list services")
		fmt.Println(body)
	default:
		fmt.Println("Usage: fides service <set|list> ...")
		os.Exit(1)
	}
}

// handleException: fides exception <create|list|revoke> — governed, time-boxed
// control waivers the change-gate honours.
func handleException(config CLIConfig, args []string) {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "create":
		cmd := flag.NewFlagSet("exception create", flag.ExitOnError)
		control := cmd.String("control", "", "control key to waive (e.g. SOC2-CC6.1)")
		reason := cmd.String("reason", "", "justification (required)")
		days := cmd.Int("days", 0, "expire in N days")
		expires := cmd.String("expires", "", "explicit expiry, RFC3339 (alternative to --days)")
		by := cmd.String("approved-by", "", "who approved the waiver")
		cmd.Parse(args[1:])
		if *control == "" || *reason == "" || (*days == 0 && *expires == "") {
			fmt.Println("Usage: fides exception create --control <key> --reason <r> (--days N | --expires <RFC3339>) [--approved-by <who>]")
			os.Exit(1)
		}
		post(config, "/api/v1/exceptions", map[string]any{
			"control_key": *control, "reason": *reason, "approved_by": *by,
			"expires_in_days": *days, "expires_at": *expires,
		}, "Exception recorded")
	case "list":
		body, err := getList(config, "/api/v1/exceptions")
		fail(err, "list exceptions")
		fmt.Println(body)
	case "revoke":
		cmd := flag.NewFlagSet("exception revoke", flag.ExitOnError)
		id := cmd.String("id", "", "exception id")
		cmd.Parse(args[1:])
		if *id == "" {
			fmt.Println("Usage: fides exception revoke --id <exception-id>")
			os.Exit(1)
		}
		post(config, "/api/v1/exceptions/"+*id+"/revoke", map[string]any{}, "Exception revoked")
	default:
		fmt.Println("Usage: fides exception <create|list|revoke> ...")
		os.Exit(1)
	}
}

// fides report --framework <name> [--format oscal] — auditor-ready framework
// report. Default output is Fides' own human-readable JSON; --format oscal
// requests a NIST OSCAL 1.x assessment-results JSON document instead (the
// machine-readable format frameworks like FedRAMP 20x mandate).
func handleReport(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("report", flag.ExitOnError)
	framework := cmd.String("framework", "", "framework name (SOC2, ISO27001, NIST-800-53, PCI-DSS, DORA, PSD2, SOX, SLSA, CRA)")
	format := cmd.String("format", "", "output format: default (human-readable JSON) or oscal")
	craIncidents := cmd.Bool("cra-incidents", false, "EU CRA 24h exploited-vulnerability / incident reporting set")
	hours := cmd.Int("hours", 24, "window in hours for --cra-incidents")
	cmd.Parse(args)
	// EU CRA 24h reporting: exploitable vulnerabilities (VEX not_affected excluded)
	// discovered in the window, with affected artifacts + running environments.
	if *craIncidents {
		body, err := getRequest(config, fmt.Sprintf("/api/v1/reports/cra-incidents?hours=%d", *hours))
		fail(err, "cra incident report")
		fmt.Println(body)
		return
	}
	if *framework == "" {
		fmt.Println("Usage: fides report --framework <name> [--format oscal]  |  fides report --cra-incidents [--hours N]")
		os.Exit(1)
	}
	path := "/api/v1/reports/framework/" + neturl.PathEscape(*framework)
	if *format != "" {
		path += "?format=" + neturl.QueryEscape(*format)
	}
	body, err := getRequest(config, path)
	fail(err, "framework report")
	fmt.Println(body)
}

// fides audit --trail <id> [--signed] [--output <file.zip>]
func handleAudit(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("audit", flag.ExitOnError)
	trail := cmd.String("trail", "", "trail UUID")
	output := cmd.String("output", "", "output zip path")
	signed := cmd.Bool("signed", false, "download a signed ZIP and detached .sig sibling")
	cmd.Parse(args)
	if *trail == "" {
		fmt.Println("Usage: fides audit --trail <id> [--signed] [--output <file.zip>]")
		os.Exit(1)
	}
	dest := *output
	if dest == "" {
		dest = "trail-" + *trail + "-audit.zip"
	}
	if *signed {
		fail(downloadSignedAudit(config, *trail, dest), "download signed audit package")
		fmt.Printf("Wrote signed audit package to %s and %s.sig\n", dest, dest)
		return
	}
	req, _ := http.NewRequest("GET", config.ServerURL+"/api/v1/trails/"+*trail+"/audit-package", nil) // #nosec G704 -- request targets the operator-configured Fides server (FIDES_SERVER_URL)
	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}
	resp, err := httpClient.Do(req) // #nosec G704 -- request targets the operator-configured Fides server (FIDES_SERVER_URL)
	fail(err, "download audit package")
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		fail(fmt.Errorf("server returned %d: %s", resp.StatusCode, string(b)), "download audit package")
	}
	f, err := os.Create(dest) // #nosec G304 G703 -- CLI writes to a user-specified output path by design
	fail(err, "create output file")
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		fail(err, "write audit package")
	}
	fmt.Printf("Wrote audit package to %s\n", dest)
}

// fides metrics [--days N]
func handleMetrics(config CLIConfig, args []string) {
	if len(args) > 0 && args[0] == "deployment-frequency" {
		cmd := flag.NewFlagSet("metrics deployment-frequency", flag.ExitOnError)
		weeks := cmd.Int("weeks", 12, "number of weeks")
		cmd.Parse(args[1:])
		body, err := getRequest(config, fmt.Sprintf("/api/v1/metrics/deployment-frequency?weeks=%d", *weeks))
		fail(err, "fetch deployment frequency")
		fmt.Println(body)
		return
	}
	if len(args) > 0 && args[0] == "compliance-correlation" {
		cmd := flag.NewFlagSet("metrics compliance-correlation", flag.ExitOnError)
		days := cmd.Int("days", 30, "window in days")
		cmd.Parse(args[1:])
		body, err := getRequest(config, fmt.Sprintf("/api/v1/metrics/compliance-correlation?days=%d", *days))
		fail(err, "fetch compliance correlation")
		fmt.Println(body)
		return
	}
	cmd := flag.NewFlagSet("metrics", flag.ExitOnError)
	days := cmd.Int("days", 30, "window in days")
	cmd.Parse(args)
	body, err := getRequest(config, fmt.Sprintf("/api/v1/metrics/dora?days=%d", *days))
	fail(err, "fetch metrics")
	fmt.Println(body)
}
