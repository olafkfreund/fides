package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/google/uuid"
)

const attestationTypesPath = "/api/v1/attestation-types"

func handleAttestationType(config CLIConfig, args []string) {
	body, err := attestationTypeCommand(config, args)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	fail(err, "attestation type")
	if body != "" {
		fmt.Println(body)
	}
}

func attestationTypeCommand(config CLIConfig, args []string) (string, error) {
	const usage = "usage: fides attestation-type <create|list|get|update|delete> [flags]"
	if len(args) == 0 {
		return "", errors.New(usage)
	}
	subcommand := args[0]
	cmd := flag.NewFlagSet("attestation-type "+subcommand, flag.ContinueOnError)
	var id, name, description, schemaFile, jqRules string
	var clearSchema bool
	switch subcommand {
	case "list":
	case "get", "delete", "update":
		cmd.StringVar(&id, "id", "", "attestation type UUID")
	case "create":
	case "help", "--help", "-h":
		return usage, nil
	default:
		return "", errors.New(usage)
	}
	if subcommand == "create" || subcommand == "update" {
		cmd.StringVar(&name, "name", "", "attestation type name")
		cmd.StringVar(&description, "description", "", "attestation type description")
		cmd.StringVar(&schemaFile, "schema", "", "path to a JSON Schema file")
		cmd.StringVar(&jqRules, "jq-rules", "", "JSON array of jq rules (use [] to clear)")
	}
	if subcommand == "update" {
		cmd.BoolVar(&clearSchema, "clear-schema", false, "remove the JSON Schema")
	}
	if err := cmd.Parse(args[1:]); err != nil {
		return "", err
	}
	if cmd.NArg() != 0 {
		return "", fmt.Errorf("unexpected argument %q", cmd.Arg(0))
	}

	path := attestationTypesPath
	switch subcommand {
	case "list":
		return getList(config, path)
	case "get", "update", "delete":
		parsedID, err := uuid.Parse(id)
		if err != nil {
			return "", errors.New("--id must be an attestation type UUID")
		}
		path += "/" + parsedID.String()
		if subcommand == "get" {
			return getRequest(config, path)
		}
		if subcommand == "delete" {
			return deleteRequest(config, path)
		}
	}

	payload := map[string]any{}
	var hasSchema, hasRules bool
	cmd.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "name", "description":
			payload[f.Name] = f.Value.String()
		case "schema":
			hasSchema = true
		case "jq-rules":
			hasRules = true
		}
	})
	if subcommand == "create" && name == "" {
		return "", errors.New("--name is required")
	}
	if clearSchema && hasSchema {
		return "", errors.New("--schema and --clear-schema are mutually exclusive")
	}
	if clearSchema {
		payload["schema"] = ""
	}
	if hasSchema {
		schema, err := os.ReadFile(schemaFile) // #nosec G304 G703 -- CLI reads the operator-supplied schema file
		if err != nil {
			return "", fmt.Errorf("read schema file: %w", err)
		}
		if !json.Valid(schema) {
			return "", errors.New("schema file must contain valid JSON")
		}
		payload["schema"] = string(schema)
	}
	if hasRules {
		var values []*string
		if err := json.Unmarshal([]byte(jqRules), &values); err != nil || values == nil {
			return "", errors.New("--jq-rules must be a JSON array of strings")
		}
		rules := make([]string, 0, len(values))
		for _, value := range values {
			if value == nil {
				return "", errors.New("--jq-rules must be a JSON array of strings")
			}
			rules = append(rules, *value)
		}
		payload["jq_rules"] = rules
	}
	if subcommand == "create" {
		return postRequest(config, path, payload)
	}
	if len(payload) == 0 {
		return "", errors.New("update requires at least one field")
	}
	return jsonRequest(config, http.MethodPatch, path, payload)
}
