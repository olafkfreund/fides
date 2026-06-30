package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
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
	req, err := http.NewRequest("GET", config.ServerURL+path, nil)
	if err != nil {
		return "", err
	}
	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}
	resp, err := httpClient.Do(req)
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
		fmt.Println("Usage: fides git-provider config --provider <github|gitlab> --host <h> --api-base <url> --token-path <ref> [--inbound-secret-path <ref>] [--disable]")
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
	if (*provider != "github" && *provider != "gitlab") || *host == "" || *apiBase == "" || *tokenPath == "" {
		fmt.Println("Error: --provider (github|gitlab), --host, --api-base, --token-path are required")
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
