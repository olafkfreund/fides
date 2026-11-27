package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

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
		body, err := getList(config, "/api/v1/tenant/service-accounts")
		fail(err, "list service accounts")
		fmt.Println(body)
	case "issue-key":
		cmd := flag.NewFlagSet("service-account issue-key", flag.ExitOnError)
		account := cmd.String("account", "", "service account UUID")
		label := cmd.String("label", "", "key label")
		expires := cmd.Int("expires-hours", 0, "key TTL in hours (0 = no expiry)")
		readOnly := cmd.Bool("read-only", false, "restrict the key to audited read routes (Viewer accounts only)")
		cmd.Parse(args[1:])
		if *account == "" {
			fmt.Println("Error: --account is required")
			os.Exit(1)
		}
		payload := map[string]any{"label": *label, "expires_hours": *expires}
		if *readOnly {
			payload["read_only"] = true
		}
		path := "/api/v1/tenant/service-accounts/" + *account + "/keys"
		body, err := postRequest(config, path, payload)
		fail(err, "issue service-account key")
		if *readOnly {
			var issued struct {
				ReadOnly bool   `json:"read_only"`
				Prefix   string `json:"prefix"`
			}
			if err := json.Unmarshal([]byte(body), &issued); err != nil || !issued.ReadOnly {
				fmt.Fprintf(os.Stderr, "Server did not confirm read-only scope. Check the server version and revoke the key (prefix %q) if issued.\n", issued.Prefix)
				os.Exit(1)
			}
		}
		fmt.Println("Save this key now — it is shown only once:")
		fmt.Println(body)
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
