package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strings"

	"fides/pkg/evidence"
)

// isEvidenceFormat reports whether name is a supported evidence report format.
func isEvidenceFormat(name string) bool {
	for _, f := range evidence.SupportedFormats {
		if f == name {
			return true
		}
	}
	return false
}

// handleAttestEvidence parses a CI/security report (JUnit/Snyk/Trivy) into a
// normalized attestation payload and records it (attaching the raw report).
func handleAttestEvidence(config CLIConfig, format string, args []string) {
	cmd := flag.NewFlagSet("attest "+format, flag.ExitOnError)
	trailID := cmd.String("trail", "", "Trail UUID")
	artSHA := cmd.String("artifact-sha", "", "Artifact SHA256 (optional)")
	name := cmd.String("name", format, "Attestation name")
	file := cmd.String("file", "", "path to the "+format+" report")
	cmd.Parse(args)

	if *trailID == "" || *file == "" {
		fmt.Printf("Error: --trail and --file are required\nUsage: fides attest %s --trail <id> --file <report> [--name <n>] [--artifact-sha <sha>]\n", format)
		os.Exit(1)
	}
	data, err := os.ReadFile(*file) // #nosec G304 G703 -- CLI reads a user-specified report file by design
	fail(err, "read report")
	result, err := evidence.Parse(format, data)
	fail(err, "parse "+format+" report")
	payload, _ := json.Marshal(result)

	respBody, err := uploadMultipart(config, *trailID, *artSHA, *name, format, string(payload), []string{*file}, false)
	fail(err, "record attestation")
	fmt.Printf("Recorded %s attestation (compliant=%v): %s\n", format, result.Compliant, respBody)
}

// getRequest performs an authenticated GET and returns the response body.
func getRequest(config CLIConfig, path string) (string, error) {
	req, err := http.NewRequest("GET", config.ServerURL+path, nil) // #nosec G704 -- request targets the operator-configured Fides server (FIDES_SERVER_URL)
	if err != nil {
		return "", err
	}
	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}
	resp, err := httpClient.Do(req) // #nosec G704 -- request targets the operator-configured Fides server (FIDES_SERVER_URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("server returned error code: %d, body: %s", resp.StatusCode, string(b))
	}
	return string(b), nil
}

// fides servicenow config|get|change-check
func handleServiceNow(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides servicenow <config|get|change-check> [flags]")
		os.Exit(1)
	}
	switch args[0] {
	case "config":
		cmd := flag.NewFlagSet("servicenow config", flag.ExitOnError)
		instanceURL := cmd.String("instance-url", "", "https://<instance>.service-now.com")
		authType := cmd.String("auth-type", "basic", "basic | oauth2")
		clientID := cmd.String("client-id", "", "OAuth client id or Basic username")
		secretPath := cmd.String("secret-path", "", "secret reference (env var or Secrets Manager id)")
		disable := cmd.Bool("disable", false, "disable the integration")
		cmd.Parse(args[1:])
		if *instanceURL == "" || *clientID == "" || *secretPath == "" || (*authType != "basic" && *authType != "oauth2") {
			fmt.Println("Error: --instance-url, --client-id, --secret-path required; --auth-type must be basic|oauth2")
			os.Exit(1)
		}
		post(config, "/api/v1/tenant/servicenow", map[string]any{
			"instance_url": *instanceURL, "auth_type": *authType, "client_id": *clientID,
			"secret_path": *secretPath, "enabled": !*disable,
		}, "ServiceNow configuration saved")
	case "get":
		body, err := getRequest(config, "/api/v1/tenant/servicenow")
		fail(err, "fetch ServiceNow config")
		fmt.Println(body)
	case "change-check":
		cmd := flag.NewFlagSet("servicenow change-check", flag.ExitOnError)
		trail := cmd.String("trail", "", "trail UUID")
		change := cmd.String("change", "", "change number, e.g. CHG0030192")
		ci := cmd.String("ci", "", "cmdb_ci name (alternative to --change)")
		cmd.Parse(args[1:])
		if *trail == "" || (*change == "" && *ci == "") {
			fmt.Println("Error: --trail and one of --change/--ci are required")
			os.Exit(1)
		}
		post(config, "/api/v1/servicenow/change-check", map[string]any{
			"trail_id": *trail, "change_number": *change, "ci": *ci,
		}, "")
	default:
		fmt.Println("Usage: fides servicenow <config|get|change-check> [flags]")
		os.Exit(1)
	}
}

// fides git-provider config
func handleGitProvider(config CLIConfig, args []string) {
	if len(args) < 1 || args[0] != "config" {
		fmt.Println("Usage: fides git-provider config --provider <github|gitlab|bitbucket|azure-devops> --host <h> --api-base <url> --token-path <ref> [--inbound-secret-path <ref>] [--disable]")
		os.Exit(1)
	}
	cmd := flag.NewFlagSet("git-provider config", flag.ExitOnError)
	provider := cmd.String("provider", "", "github | gitlab")
	host := cmd.String("host", "", "provider host, e.g. github.com")
	apiBase := cmd.String("api-base", "", "API base URL")
	tokenPath := cmd.String("token-path", "", "API token secret reference")
	inboundSecret := cmd.String("inbound-secret-path", "", "inbound webhook secret reference (optional)")
	disable := cmd.Bool("disable", false, "disable the provider")
	cmd.Parse(args[1:])
	if !map[string]bool{"github": true, "gitlab": true, "bitbucket": true, "azure-devops": true}[*provider] || *host == "" || *apiBase == "" || *tokenPath == "" {
		fmt.Println("Error: --provider (github|gitlab|bitbucket|azure-devops), --host, --api-base, --token-path are required")
		os.Exit(1)
	}
	post(config, "/api/v1/tenant/git-providers", map[string]any{
		"provider": *provider, "host": *host, "api_base": *apiBase, "token_path": *tokenPath,
		"inbound_secret_path": *inboundSecret, "enabled": !*disable,
	}, "Git provider configuration saved")
}

// fides webhook config
func handleWebhook(config CLIConfig, args []string) {
	if len(args) < 1 || args[0] != "config" {
		fmt.Println("Usage: fides webhook config --name <n> --url <https-url> --secret-path <ref> [--events e1,e2] [--disable]")
		os.Exit(1)
	}
	cmd := flag.NewFlagSet("webhook config", flag.ExitOnError)
	name := cmd.String("name", "", "webhook name")
	url := cmd.String("url", "", "https endpoint URL")
	secretPath := cmd.String("secret-path", "", "HMAC signing secret reference")
	events := cmd.String("events", "", "comma-separated event types (empty = all)")
	disable := cmd.Bool("disable", false, "disable the webhook")
	cmd.Parse(args[1:])
	if *name == "" || !strings.HasPrefix(*url, "https://") || *secretPath == "" {
		fmt.Println("Error: --name, https --url, and --secret-path are required")
		os.Exit(1)
	}
	var eventTypes []string
	if *events != "" {
		eventTypes = strings.Split(*events, ",")
	}
	post(config, "/api/v1/tenant/webhooks", map[string]any{
		"name": *name, "url": *url, "secret_path": *secretPath,
		"event_types": eventTypes, "enabled": !*disable,
	}, "Webhook configuration saved")
}

// deleteRequest performs an authenticated DELETE.
func deleteRequest(config CLIConfig, path string) (string, error) {
	req, err := http.NewRequest("DELETE", config.ServerURL+path, nil) // #nosec G704 -- request targets the operator-configured Fides server (FIDES_SERVER_URL)
	if err != nil {
		return "", err
	}
	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}
	resp, err := httpClient.Do(req) // #nosec G704 -- request targets the operator-configured Fides server (FIDES_SERVER_URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("server returned error code: %d, body: %s", resp.StatusCode, string(b))
	}
	return string(b), nil
}

// fides service-account create|list|issue-key|revoke-key
func handleServiceAccount(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides service-account <create|list|issue-key|revoke-key> [flags]")
		os.Exit(1)
	}
	switch args[0] {
	case "create":
		cmd := flag.NewFlagSet("service-account create", flag.ExitOnError)
		name := cmd.String("name", "", "service account name")
		role := cmd.String("role", "Writer", "Admin|Auditor|Writer|Viewer")
		cmd.Parse(args[1:])
		if *name == "" {
			fmt.Println("Error: --name is required")
			os.Exit(1)
		}
		post(config, "/api/v1/tenant/service-accounts", map[string]any{"name": *name, "role": *role}, "")
	case "list":
		body, err := getRequest(config, "/api/v1/tenant/service-accounts")
		fail(err, "list service accounts")
		fmt.Println(body)
	case "issue-key":
		cmd := flag.NewFlagSet("service-account issue-key", flag.ExitOnError)
		account := cmd.String("account", "", "service account UUID")
		label := cmd.String("label", "", "key label")
		expires := cmd.Int("expires-hours", 0, "key TTL in hours (0 = no expiry)")
		cmd.Parse(args[1:])
		if *account == "" {
			fmt.Println("Error: --account is required")
			os.Exit(1)
		}
		fmt.Println("Save this key now — it is shown only once:")
		post(config, "/api/v1/tenant/service-accounts/"+*account+"/keys",
			map[string]any{"label": *label, "expires_hours": *expires}, "")
	case "revoke-key":
		cmd := flag.NewFlagSet("service-account revoke-key", flag.ExitOnError)
		account := cmd.String("account", "", "service account UUID")
		key := cmd.String("key", "", "key UUID")
		cmd.Parse(args[1:])
		if *account == "" || *key == "" {
			fmt.Println("Error: --account and --key are required")
			os.Exit(1)
		}
		body, err := deleteRequest(config, "/api/v1/tenant/service-accounts/"+*account+"/keys/"+*key)
		fail(err, "revoke key")
		fmt.Println(body)
	default:
		fmt.Println("Usage: fides service-account <create|list|issue-key|revoke-key> [flags]")
		os.Exit(1)
	}
}

// fides slack config --secret-path <ref> [--disable]
func handleSlack(config CLIConfig, args []string) {
	if len(args) < 1 || args[0] != "config" {
		fmt.Println("Usage: fides slack config --secret-path <ref> [--disable]")
		os.Exit(1)
	}
	cmd := flag.NewFlagSet("slack config", flag.ExitOnError)
	secretPath := cmd.String("secret-path", "", "Slack incoming-webhook URL secret reference")
	disable := cmd.Bool("disable", false, "disable Slack notifications")
	cmd.Parse(args[1:])
	if *secretPath == "" {
		fmt.Println("Error: --secret-path is required")
		os.Exit(1)
	}
	post(config, "/api/v1/tenant/slack", map[string]any{"webhook_secret_path": *secretPath, "enabled": !*disable}, "Slack configuration saved")
}

// fides approve --trail <id> [--reason r] — record a segregation-of-duties approval.
func handleApprove(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("approve", flag.ExitOnError)
	trail := cmd.String("trail", "", "trail UUID")
	reason := cmd.String("reason", "", "approval reason")
	cmd.Parse(args)
	if *trail == "" {
		fmt.Println("Usage: fides approve --trail <id> [--reason <r>]")
		os.Exit(1)
	}
	post(config, "/api/v1/trails/"+*trail+"/approvals", map[string]any{"reason": *reason}, "Approval recorded")
}

// fides report --framework <name> [--format oscal] — auditor-ready framework
// report. Default output is Fides' own human-readable JSON; --format oscal
// requests a NIST OSCAL 1.x assessment-results JSON document instead (the
// machine-readable format frameworks like FedRAMP 20x mandate).
func handleReport(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("report", flag.ExitOnError)
	framework := cmd.String("framework", "", "framework name (SOC2, ISO27001, NIST-800-53, PCI-DSS, DORA, PSD2, SOX)")
	format := cmd.String("format", "", "output format: default (human-readable JSON) or oscal")
	cmd.Parse(args)
	if *framework == "" {
		fmt.Println("Usage: fides report --framework <name> [--format oscal]")
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
		os.Exit(2) // non-zero so CI / a change pipeline can gate on the verdict
	}
}

// fides control add|list|coverage|archive|unarchive
func handleControl(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides control <add|list|coverage|frameworks|import|enforce|archive|unarchive> [flags]")
		os.Exit(1)
	}
	switch args[0] {
	case "add":
		cmd := flag.NewFlagSet("control add", flag.ExitOnError)
		key := cmd.String("key", "", "control key, e.g. SOC2-CC6.1")
		name := cmd.String("name", "", "control name")
		desc := cmd.String("description", "", "description")
		framework := cmd.String("framework", "", "SOC2 | ISO27001 | FDA-21CFR11")
		require := cmd.String("require", "", "comma-separated attestation types")
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
		body, err := getRequest(config, p)
		fail(err, "list controls")
		fmt.Println(body)
	case "coverage":
		body, err := getRequest(config, "/api/v1/controls/coverage")
		fail(err, "controls coverage")
		fmt.Println(body)
	case "frameworks":
		body, err := getRequest(config, "/api/v1/frameworks")
		fail(err, "list frameworks")
		fmt.Println(body)
	case "import":
		cmd := flag.NewFlagSet("control import", flag.ExitOnError)
		framework := cmd.String("framework", "", "framework name (SOC2, ISO27001, NIST-800-53, PCI-DSS, DORA, PSD2, SOX)")
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
			raw, err := getRequest(config, "/api/v1/controls")
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
	cmd := flag.NewFlagSet("metrics", flag.ExitOnError)
	days := cmd.Int("days", 30, "window in days")
	cmd.Parse(args)
	body, err := getRequest(config, fmt.Sprintf("/api/v1/metrics/dora?days=%d", *days))
	fail(err, "fetch metrics")
	fmt.Println(body)
}

// fides flow list | trails --flow <id> | artifacts --flow <id>
func handleFlow(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides flow <list|trails|artifacts> [--flow <id>]")
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		body, err := getRequest(config, "/api/v1/flows")
		fail(err, "list flows")
		fmt.Println(body)
	case "trails", "artifacts":
		cmd := flag.NewFlagSet("flow "+args[0], flag.ExitOnError)
		flow := cmd.String("flow", "", "flow UUID")
		cmd.Parse(args[1:])
		if *flow == "" {
			fmt.Println("Error: --flow is required")
			os.Exit(1)
		}
		body, err := getRequest(config, "/api/v1/flows/"+*flow+"/"+args[0])
		fail(err, "list flow "+args[0])
		fmt.Println(body)
	default:
		fmt.Println("Usage: fides flow <list|trails|artifacts> [--flow <id>]")
		os.Exit(1)
	}
}

// fides logical-env create|list|add-member|state
func handleLogicalEnv(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides logical-env <create|list|add-member|state> [--name --id --env]")
		os.Exit(1)
	}
	cmd := flag.NewFlagSet("logical-env "+args[0], flag.ExitOnError)
	name := cmd.String("name", "", "logical environment name")
	desc := cmd.String("description", "", "description")
	id := cmd.String("id", "", "logical environment UUID")
	env := cmd.String("env", "", "physical environment UUID")
	cmd.Parse(args[1:])
	switch args[0] {
	case "create":
		if *name == "" {
			fmt.Println("Error: --name is required")
			os.Exit(1)
		}
		post(config, "/api/v1/logical-environments", map[string]any{"name": *name, "description": *desc}, "")
	case "list":
		body, err := getRequest(config, "/api/v1/logical-environments")
		fail(err, "list logical environments")
		fmt.Println(body)
	case "add-member":
		if *id == "" || *env == "" {
			fmt.Println("Error: --id and --env are required")
			os.Exit(1)
		}
		post(config, "/api/v1/logical-environments/"+*id+"/members", map[string]any{"environment_id": *env}, "Member added")
	case "state":
		if *id == "" {
			fmt.Println("Error: --id is required")
			os.Exit(1)
		}
		body, err := getRequest(config, "/api/v1/logical-environments/"+*id+"/state")
		fail(err, "logical env state")
		fmt.Println(body)
	default:
		fmt.Println("Usage: fides logical-env <create|list|add-member|state>")
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
	require := cmd.String("require", "", "comma-separated required attestation types")
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
		body, err := getRequest(config, base+"/policies")
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
			os.Exit(2) // non-zero so CI can gate a deploy
		}
	default:
		fmt.Println("Usage: fides policy <add|list|check> --env <id>")
		os.Exit(1)
	}
}

// fides audit --trail <id> [--output <file.zip>]
func handleAudit(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("audit", flag.ExitOnError)
	trail := cmd.String("trail", "", "trail UUID")
	output := cmd.String("output", "", "output zip path")
	cmd.Parse(args)
	if *trail == "" {
		fmt.Println("Usage: fides audit --trail <id> [--output <file.zip>]")
		os.Exit(1)
	}
	dest := *output
	if dest == "" {
		dest = "trail-" + *trail + "-audit.zip"
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

// fides search artifacts|attestations
func handleSearch(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides search <artifacts|attestations> [--sha --commit --name | --type --trail --compliant]")
		os.Exit(1)
	}
	cmd := flag.NewFlagSet("search "+args[0], flag.ExitOnError)
	sha := cmd.String("sha", "", "artifact SHA256 prefix")
	commit := cmd.String("commit", "", "git commit")
	name := cmd.String("name", "", "artifact name (substring)")
	typ := cmd.String("type", "", "attestation type name")
	trail := cmd.String("trail", "", "trail UUID")
	compliant := cmd.String("compliant", "", "true|false")
	cmd.Parse(args[1:])

	q := neturl.Values{}
	var path string
	switch args[0] {
	case "artifacts":
		path = "/api/v1/search/artifacts"
		setIf(q, "sha", *sha)
		setIf(q, "commit", *commit)
		setIf(q, "name", *name)
	case "attestations":
		path = "/api/v1/search/attestations"
		setIf(q, "type", *typ)
		setIf(q, "trail", *trail)
		setIf(q, "compliant", *compliant)
	default:
		fmt.Println("Usage: fides search <artifacts|attestations>")
		os.Exit(1)
	}
	body, err := getRequest(config, path+"?"+q.Encode())
	fail(err, "search")
	fmt.Println(body)
}

// stringSlice collects a repeatable flag (e.g. --rule ... --rule ...).
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

// fides env verify --env <id> --server <name> --tool <t> --rule '...' [--rules-file <f>]
func handleEnvVerify(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("env verify", flag.ExitOnError)
	env := cmd.String("env", "", "environment UUID")
	server := cmd.String("server", "", "MCP server/connection name")
	tool := cmd.String("tool", "get_pods", "MCP tool name")
	rulesFile := cmd.String("rules-file", "", "file with one jq rule per line")
	var rules stringSlice
	cmd.Var(&rules, "rule", "a jq compliance rule (repeatable)")
	cmd.Parse(args)
	if *env == "" || *server == "" || *tool == "" {
		fmt.Println("Usage: fides env verify --env <id> --server <name> --tool <t> --rule '.pods[].status == \"Ready\"' [--rules-file <f>]")
		os.Exit(1)
	}
	rl := []string(rules)
	if *rulesFile != "" {
		data, err := os.ReadFile(*rulesFile) // #nosec G304 G703 -- CLI reads a user-specified rules file by design
		fail(err, "read rules file")
		for _, line := range strings.Split(string(data), "\n") {
			if s := strings.TrimSpace(line); s != "" {
				rl = append(rl, s)
			}
		}
	}
	if len(rl) == 0 {
		fmt.Println("Error: provide at least one --rule or a --rules-file")
		os.Exit(1)
	}
	body, err := postRequest(config, "/api/v1/environments/mcp/verify", map[string]any{
		"environment_id": *env, "server_name": *server, "tool_name": *tool,
		"arguments": map[string]any{}, "rules": rl,
	})
	fail(err, "verify environment compliance")
	fmt.Println(body)
	if strings.Contains(body, "\"compliant\":false") {
		os.Exit(2) // non-zero so CI can gate on runtime compliance
	}
}

// fides env diff --env <id> [--from <snap> --to <snap>]
func handleEnvDiff(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("env diff", flag.ExitOnError)
	env := cmd.String("env", "", "environment UUID")
	from := cmd.String("from", "", "from snapshot UUID (default: 2nd most recent)")
	to := cmd.String("to", "", "to snapshot UUID (default: most recent)")
	cmd.Parse(args)
	if *env == "" {
		fmt.Println("Usage: fides env diff --env <id> [--from <snap> --to <snap>]")
		os.Exit(1)
	}
	q := neturl.Values{}
	setIf(q, "from", *from)
	setIf(q, "to", *to)
	body, err := getRequest(config, "/api/v1/environments/"+*env+"/snapshots/diff?"+q.Encode())
	fail(err, "snapshot diff")
	fmt.Println(body)
}

func setIf(q neturl.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

// fides allowlist add|list|check|remove
func handleAllowlist(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides allowlist <add|list|check|remove> --env <id> [--sha <sha>] [--reason <r>]")
		os.Exit(1)
	}
	cmd := flag.NewFlagSet("allowlist "+args[0], flag.ExitOnError)
	env := cmd.String("env", "", "environment UUID")
	sha := cmd.String("sha", "", "artifact SHA256")
	reason := cmd.String("reason", "", "approval reason")
	cmd.Parse(args[1:])
	if *env == "" {
		fmt.Println("Error: --env is required")
		os.Exit(1)
	}
	base := "/api/v1/environments/" + *env + "/allowlist"
	switch args[0] {
	case "add":
		if *sha == "" {
			fmt.Println("Error: --sha is required")
			os.Exit(1)
		}
		post(config, base, map[string]any{"artifact_sha256": *sha, "reason": *reason}, "Artifact approved for the environment")
	case "list":
		body, err := getRequest(config, base)
		fail(err, "list allowlist")
		fmt.Println(body)
	case "check":
		if *sha == "" {
			fmt.Println("Error: --sha is required")
			os.Exit(1)
		}
		body, err := getRequest(config, base+"?sha="+*sha)
		fail(err, "check allowlist")
		fmt.Println(body)
		if strings.Contains(body, "\"approved\":false") {
			os.Exit(2) // non-zero so CI can gate a deploy on approval
		}
	case "remove":
		if *sha == "" {
			fmt.Println("Error: --sha is required")
			os.Exit(1)
		}
		body, err := deleteRequest(config, base+"/"+*sha)
		fail(err, "remove allowlist")
		fmt.Println(body)
	default:
		fmt.Println("Usage: fides allowlist <add|list|check|remove> --env <id> [--sha <sha>]")
		os.Exit(1)
	}
}

// fides verify-chain --trail <id>
func handleVerifyChain(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("verify-chain", flag.ExitOnError)
	trailID := cmd.String("trail", "", "trail UUID")
	cmd.Parse(args)
	if *trailID == "" {
		fmt.Println("Usage: fides verify-chain --trail <trail_id>")
		os.Exit(1)
	}
	body, err := getRequest(config, "/api/v1/trails/"+*trailID+"/verify-chain")
	fail(err, "verify chain")
	fmt.Println(body)
	if strings.Contains(body, "\"valid\":false") {
		os.Exit(2) // non-zero so CI fails on a broken chain
	}
}

// fides user set-password
func handleUser(config CLIConfig, args []string) {
	if len(args) < 1 || args[0] != "set-password" {
		fmt.Println("Usage: fides user set-password --user <user_id> --password <password>")
		os.Exit(1)
	}
	cmd := flag.NewFlagSet("user set-password", flag.ExitOnError)
	userID := cmd.String("user", "", "user UUID")
	password := cmd.String("password", "", "new password (min 8 chars)")
	cmd.Parse(args[1:])
	if *userID == "" || len(*password) < 8 {
		fmt.Println("Error: --user is required and --password must be at least 8 characters")
		os.Exit(1)
	}
	post(config, "/api/v1/tenant/users/"+*userID+"/password", map[string]any{"password": *password}, "Password updated")
}

// post is a small helper: POST json, print success message (or the body), exit on error.
func post(config CLIConfig, path string, payload any, successMsg string) {
	body, err := postRequest(config, path, payload)
	fail(err, "request to "+path)
	if successMsg != "" {
		fmt.Println(successMsg)
	} else {
		fmt.Println(body)
	}
}

func fail(err error, what string) {
	if err != nil {
		fmt.Printf("Failed: %s: %v\n", what, err)
		os.Exit(1)
	}
}
