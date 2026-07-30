package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"fides/pkg/cliout"
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

// handleSBOM is the `fides sbom <subcommand>` entrypoint.
func handleSBOM(_ CLIConfig, args []string) {
	if len(args) >= 1 && args[0] == "diff" {
		handleSBOMDiff(args[1:])
		return
	}
	fmt.Println("Usage: fides sbom diff <old.json> <new.json> [--json]")
	os.Exit(1)
}

// handleSBOMDiff compares two local SBOM files (CycloneDX/SPDX, auto-detected)
// and reports components added, removed, and version-changed — the CI check for
// "did this build add or bump dependencies?". Offline; no server round-trip.
func handleSBOMDiff(args []string) {
	// Manual parse so --json works in any position (stdlib flag stops at the
	// first positional, which would reject `sbom diff a.json b.json --json`).
	asJSON := false
	var files []string
	for _, a := range args {
		switch a {
		case "--json", "-json":
			asJSON = true
		default:
			files = append(files, a)
		}
	}
	if len(files) != 2 {
		fmt.Println("Usage: fides sbom diff <old.json> <new.json> [--json]")
		os.Exit(1)
	}
	d := diffSBOM(parseSBOMFile(files[0]), parseSBOMFile(files[1]))
	if asJSON {
		fail(cliout.Render(os.Stdout, "json", d), "encode diff")
		return
	}
	printSBOMDiff(files[0], files[1], d)
}

func parseSBOMFile(path string) []evidence.Component {
	data, err := os.ReadFile(path) // #nosec G304 G703 -- CLI reads a user-specified SBOM by design
	fail(err, "read SBOM "+path)
	r, err := evidence.ParseSBOM(data)
	fail(err, "parse SBOM "+path)
	return r.Components
}

type sbomChange struct {
	Name string `json:"name"`
	From string `json:"from_version"`
	To   string `json:"to_version"`
}

type sbomDiff struct {
	Added   []evidence.Component `json:"added"`
	Removed []evidence.Component `json:"removed"`
	Changed []sbomChange         `json:"changed"`
}

// diffSBOM keys components by (case-insensitive) name so a version bump shows as
// "changed" rather than a spurious add+remove.
// ponytail: name is the identity key; two distinct components sharing a name
// (rare) collapse — switch to PURL-without-version if that ever bites.
func diffSBOM(oldC, newC []evidence.Component) sbomDiff {
	oldByKey := make(map[string]evidence.Component, len(oldC))
	for _, c := range oldC {
		oldByKey[strings.ToLower(c.Name)] = c
	}
	newByKey := make(map[string]evidence.Component, len(newC))
	for _, c := range newC {
		newByKey[strings.ToLower(c.Name)] = c
	}

	var d sbomDiff
	for k, nc := range newByKey {
		oc, ok := oldByKey[k]
		switch {
		case !ok:
			d.Added = append(d.Added, nc)
		case oc.Version != nc.Version:
			d.Changed = append(d.Changed, sbomChange{Name: nc.Name, From: oc.Version, To: nc.Version})
		}
	}
	for k, oc := range oldByKey {
		if _, ok := newByKey[k]; !ok {
			d.Removed = append(d.Removed, oc)
		}
	}
	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].Name < d.Added[j].Name })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].Name < d.Removed[j].Name })
	sort.Slice(d.Changed, func(i, j int) bool { return d.Changed[i].Name < d.Changed[j].Name })
	return d
}

func printSBOMDiff(oldName, newName string, d sbomDiff) {
	fmt.Printf("SBOM diff: %s -> %s\n", oldName, newName)
	fmt.Printf("  +%d added  -%d removed  ~%d changed\n\n", len(d.Added), len(d.Removed), len(d.Changed))
	for _, c := range d.Added {
		fmt.Printf("  + %s@%s\n", c.Name, c.Version)
	}
	for _, c := range d.Removed {
		fmt.Printf("  - %s@%s\n", c.Name, c.Version)
	}
	for _, c := range d.Changed {
		fmt.Printf("  ~ %s %s -> %s\n", c.Name, c.From, c.To)
	}
	if len(d.Added)+len(d.Removed)+len(d.Changed) == 0 {
		fmt.Println("  no component changes")
	}
}
