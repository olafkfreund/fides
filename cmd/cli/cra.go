package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/google/uuid"
)

func handleCRA(config CLIConfig, args []string) {
	if len(args) == 0 {
		fail(fmt.Errorf("expected list, get, create, correct, export, or submit"), "CRA cases")
	}
	cmd := flag.NewFlagSet("cra "+args[0], flag.ExitOnError)
	method, path := http.MethodGet, "/api/v1/cra/cases"
	var caseID, file *string
	switch args[0] {
	case "list":
	case "get", "correct", "export", "submit":
		caseID = cmd.String("case", "", "CRA case UUID")
	case "create":
	default:
		fail(fmt.Errorf("unknown subcommand %q", args[0]), "CRA cases")
	}
	switch args[0] {
	case "create", "export", "submit":
		method = http.MethodPost
	case "correct":
		method = http.MethodPatch
	}
	if method != http.MethodGet {
		file = cmd.String("file", "", "path to the JSON request")
	}
	cmd.Parse(args[1:])
	if cmd.NArg() != 0 {
		fail(fmt.Errorf("unexpected positional arguments"), "CRA cases")
	}
	if caseID != nil {
		id, err := uuid.Parse(*caseID)
		fail(err, "--case must be a valid UUID")
		path += "/" + id.String()
	}
	switch args[0] {
	case "export":
		path += "/exports"
	case "submit":
		path += "/submissions"
	}

	var body string
	var err error
	if file == nil {
		if args[0] == "list" {
			body, err = getList(config, path)
		} else {
			body, err = getRequest(config, path)
		}
	} else {
		if *file == "" {
			fail(fmt.Errorf("--file is required"), "CRA cases")
		}
		payload, readErr := os.ReadFile(*file) // #nosec G304 G703 -- the operator explicitly supplies the CLI request file.
		fail(readErr, "read CRA request")
		body, err = jsonRequest(config, method, path, json.RawMessage(payload))
	}
	fail(err, "CRA "+args[0])
	fmt.Println(body)
}
