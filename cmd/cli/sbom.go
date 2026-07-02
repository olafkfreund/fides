package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"fides/pkg/evidence"
)

// handleAttestSBOM parses a CycloneDX or SPDX JSON SBOM into a normalized
// attestation payload (with a per-component breakdown) and records it,
// attaching the raw SBOM file as evidence. Unlike the other `fides attest
// <format>` verbs, --trail is optional: the server resolves it from the
// artifact's own trail when omitted, since components are recorded against
// the artifact.
func handleAttestSBOM(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("attest sbom", flag.ExitOnError)
	trailID := cmd.String("trail", "", "Trail UUID (optional; resolved from the artifact when omitted)")
	artSHA := cmd.String("artifact-sha", "", "Artifact SHA256 (required)")
	name := cmd.String("name", "sbom", "Attestation name")
	file := cmd.String("file", "", "path to the CycloneDX/SPDX JSON SBOM")
	cmd.Parse(args)

	if *artSHA == "" || *file == "" {
		fmt.Println("Error: --artifact-sha and --file are required")
		fmt.Println("Usage: fides attest sbom --file <bom.json> --artifact-sha <sha256> [--trail <id>] [--name <n>]")
		os.Exit(1)
	}

	data, err := os.ReadFile(*file) // #nosec G304 G703 -- CLI reads a user-specified report file by design
	fail(err, "read SBOM file")
	result, err := evidence.ParseSBOM(data)
	fail(err, "parse SBOM")
	payload, err := json.Marshal(result)
	fail(err, "encode SBOM result")

	// type_name is fixed at "sbom-cyclonedx" (regardless of whether the source
	// document was CycloneDX or SPDX) to match the evidence type the built-in
	// control frameworks already require for "software bill of materials
	// produced" (see pkg/api/framework_catalogs.go); the detected format is
	// still recorded in the normalized payload's "format" field.
	respBody, err := uploadMultipart(config, *trailID, *artSHA, *name, "sbom-cyclonedx", string(payload), []string{*file}, false)
	fail(err, "record SBOM attestation")
	fmt.Printf("Recorded sbom attestation (format=%s, %d components): %s\n", result.Format, len(result.Components), respBody)
}
