package main

import (
	"encoding/json"
	"flag"
	"fmt"
	neturl "net/url"
	"os"
	"strings"
)

// fides servicenow config|get|change-check|link-control
func handleServiceNow(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides servicenow <config|get|change-check|link-control|anchor-deployment|grounding|mcp> [flags]")
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
	case "link-control":
		cmd := flag.NewFlagSet("servicenow link-control", flag.ExitOnError)
		trail := cmd.String("trail", "", "trail UUID")
		change := cmd.String("change", "", "change number, e.g. CHG0030192")
		control := cmd.String("control", "", "control key, e.g. SOC2-CC7.1")
		attestation := cmd.String("attestation", "", "attestation UUID (optional; defaults to the trail's most recent attestation)")
		cmd.Parse(args[1:])
		if *trail == "" || *change == "" || *control == "" {
			fmt.Println("Error: --trail, --change, and --control are required")
			os.Exit(1)
		}
		post(config, "/api/v1/servicenow/link-control", map[string]any{
			"trail_id": *trail, "change_number": *change, "control": *control, "attestation_id": *attestation,
		}, "")
	case "anchor-deployment":
		cmd := flag.NewFlagSet("servicenow anchor-deployment", flag.ExitOnError)
		trail := cmd.String("trail", "", "trail UUID")
		change := cmd.String("change", "", "change number, e.g. CHG0030192 (resolves the CI via change_request.cmdb_ci)")
		ci := cmd.String("ci", "", "cmdb_ci name (alternative/fallback to --change)")
		buildLog := cmd.String("build-log", "", "pointer to the build log (CI run URL, etc.)")
		cmd.Parse(args[1:])
		if *trail == "" || (*change == "" && *ci == "") {
			fmt.Println("Error: --trail and one of --change/--ci are required")
			os.Exit(1)
		}
		post(config, "/api/v1/servicenow/deployment-anchor", map[string]any{
			"trail_id": *trail, "change_number": *change, "ci": *ci, "build_log_ref": *buildLog,
		}, "")
	case "grounding":
		cmd := flag.NewFlagSet("servicenow grounding", flag.ExitOnError)
		change := cmd.String("change", "", "change number, e.g. CHG0030192")
		cmd.Parse(args[1:])
		if *change == "" {
			fmt.Println("Error: --change is required")
			os.Exit(1)
		}
		body, err := getRequest(config, "/api/v1/servicenow/grounding?change="+neturl.QueryEscape(*change))
		fail(err, "grounding")
		fmt.Println(body)
	case "mcp":
		handleServiceNowMCP(config, args[1:])
	default:
		fmt.Println("Usage: fides servicenow <config|get|change-check|link-control|anchor-deployment|grounding|mcp> [flags]")
		os.Exit(1)
	}
}

// handleServiceNowMCP drives the ServiceNow MCP client subcommands: discover
// MCP servers, do a governed record lookup, and list/call governed tools.
func handleServiceNowMCP(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides servicenow mcp <servers|lookup|tools|call> [flags]")
		os.Exit(1)
	}
	switch args[0] {
	case "servers":
		body, err := getRequest(config, "/api/v1/servicenow/mcp/servers")
		fail(err, "list ServiceNow MCP servers")
		fmt.Println(body)
	case "lookup":
		cmd := flag.NewFlagSet("servicenow mcp lookup", flag.ExitOnError)
		table := cmd.String("table", "", "ServiceNow table, e.g. change_request | cmdb_ci | sn_compliance_control")
		query := cmd.String("query", "", "encoded query (optional)")
		limit := cmd.Int("limit", 10, "max records")
		cmd.Parse(args[1:])
		if *table == "" {
			fmt.Println("Error: --table is required")
			os.Exit(1)
		}
		post(config, "/api/v1/servicenow/mcp/lookup", map[string]any{
			"table": *table, "query": *query, "limit": *limit,
		}, "")
	case "tools":
		cmd := flag.NewFlagSet("servicenow mcp tools", flag.ExitOnError)
		server := cmd.String("server", "", "MCP server name (default sn_mcp_server_default)")
		cmd.Parse(args[1:])
		post(config, "/api/v1/servicenow/mcp/tools", map[string]any{"server": *server}, "")
	case "call":
		cmd := flag.NewFlagSet("servicenow mcp call", flag.ExitOnError)
		server := cmd.String("server", "", "MCP server name (default sn_mcp_server_default)")
		tool := cmd.String("tool", "", "tool name")
		argsJSON := cmd.String("args", "", "tool arguments as a JSON object")
		cmd.Parse(args[1:])
		if *tool == "" {
			fmt.Println("Error: --tool is required")
			os.Exit(1)
		}
		payload := map[string]any{"server": *server, "tool": *tool}
		if *argsJSON != "" {
			var a any
			if err := json.Unmarshal([]byte(*argsJSON), &a); err != nil {
				fmt.Println("Error: --args must be valid JSON:", err)
				os.Exit(1)
			}
			payload["arguments"] = a
		}
		post(config, "/api/v1/servicenow/mcp/call", payload, "")
	default:
		fmt.Println("Usage: fides servicenow mcp <servers|lookup|tools|call> [flags]")
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
