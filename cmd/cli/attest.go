package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"fides/pkg/crypto"
	"fides/pkg/evidence"
)

func handleAttest(config CLIConfig, args []string) {
	// SBOM ingestion: `fides attest sbom --file <bom.json> --artifact-sha <sha> [--trail <id>]`.
	if len(args) > 0 && args[0] == "sbom" {
		handleAttestSBOM(config, args[1:])
		return
	}

	// Format-specific evidence: `fides attest junit|snyk|trivy --file <report> --trail <id>`.
	if len(args) > 0 && isEvidenceFormat(args[0]) {
		handleAttestEvidence(config, args[0], args[1:])
		return
	}
	// Platform-native provenance ingest: `fides attest fetch --provider github|gitlab ...`.
	if len(args) > 0 && args[0] == "fetch" {
		handleAttestFetch(config, args[1:])
		return
	}
	// AI-authored-code provenance: `fides attest authorship --trail <id> [--commit <ref>] [--reviewer <name>]`.
	if len(args) > 0 && args[0] == "authorship" {
		handleAttestAuthorship(config, args[1:])
		return
	}
	// Branch-protection: read the git host's protection rules and record them as
	// evidence: `fides attest branch-protection --trail <id> --repo owner/repo [--branch main]`.
	if len(args) > 0 && args[0] == "branch-protection" {
		cmd := flag.NewFlagSet("attest branch-protection", flag.ExitOnError)
		trailID := cmd.String("trail", "", "Trail UUID")
		repo := cmd.String("repo", "", "owner/repo (github) or group/project (gitlab)")
		branch := cmd.String("branch", "main", "branch to check")
		provider := cmd.String("provider", "", "github | gitlab (optional; default = org's first provider)")
		cmd.Parse(args[1:])
		if *trailID == "" || *repo == "" {
			fmt.Println("Usage: fides attest branch-protection --trail <id> --repo <owner/repo> [--branch main] [--provider github|gitlab]")
			os.Exit(1)
		}
		post(config, "/api/v1/verify-branch-protection", map[string]any{
			"trail_id": *trailID, "repo": *repo, "branch": *branch, "provider": *provider,
		}, "")
		return
	}

	cmd := flag.NewFlagSet("attest", flag.ExitOnError)
	trailID := cmd.String("trail", "", "Trail UUID")
	artSHA := cmd.String("artifact-sha", "", "Artifact SHA256")
	name := cmd.String("name", "", "Attestation Name (e.g., snyk-scan, unit-tests)")
	typeName := cmd.String("type", "", "Attestation Type Name (template check)")
	payloadData := cmd.String("payload", "", "JSON string or path to JSON metadata file")
	attachments := cmd.String("attachments", "", "Comma-separated list of evidence file attachments")
	encryptFlag := cmd.Bool("encrypt", false, "Encrypt the attestation payload using FIDES_ENCRYPTION_KEY")

	cmd.Parse(args)

	if *trailID == "" || *name == "" || *typeName == "" || *payloadData == "" {
		fmt.Println("Error: --trail, --name, --type, and --payload are required")
		cmd.Usage()
		os.Exit(1)
	}

	// Read payload
	var rawPayload string
	if strings.HasSuffix(*payloadData, ".json") {
		content, err := os.ReadFile(*payloadData)
		if err != nil {
			fmt.Printf("Failed to read payload file: %v\n", err)
			os.Exit(1)
		}
		rawPayload = string(content)
	} else {
		rawPayload = *payloadData
	}

	var isEncrypted bool
	encryptionKeyEnv := os.Getenv("FIDES_ENCRYPTION_KEY")
	if *encryptFlag || encryptionKeyEnv != "" {
		if encryptionKeyEnv == "" {
			fmt.Println("Error: Encryption requires FIDES_ENCRYPTION_KEY environment variable to be set")
			os.Exit(1)
		}
		key, err := crypto.DeriveKey(encryptionKeyEnv)
		if err != nil {
			fmt.Printf("Failed to derive encryption key: %v\n", err)
			os.Exit(1)
		}
		encryptedPayload, err := crypto.Encrypt([]byte(rawPayload), key)
		if err != nil {
			fmt.Printf("Failed to encrypt payload: %v\n", err)
			os.Exit(1)
		}
		rawPayload = encryptedPayload
		isEncrypted = true
		fmt.Println("Payload successfully encrypted using AES-256-GCM.")
	}

	// Make call
	var files []string
	if *attachments != "" {
		files = strings.Split(*attachments, ",")
	}

	respBody, err := uploadMultipart(config, *trailID, *artSHA, *name, *typeName, rawPayload, files, isEncrypted)
	if err != nil {
		fmt.Printf("Failed to report attestation: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully recorded attestation: %s\n", respBody)
}

// isEvidenceFormat reports whether name is a supported evidence report format.
func isEvidenceFormat(name string) bool {
	return slices.Contains(evidence.SupportedFormats, name)
}

// evidenceTypeName maps a parse format to the canonical attestation type_name
// that framework controls require. Most formats map 1:1, but SLSA provenance
// is recorded as "slsa-provenance" so that both `fides attest slsa` (local
// report) and `fides attest fetch` (platform-native) land under one type_name
// the change gate and control catalogs recognize.
func evidenceTypeName(format string) string {
	if format == "slsa" {
		return "slsa-provenance"
	}
	return format
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

	respBody, err := uploadMultipart(config, *trailID, *artSHA, *name, evidenceTypeName(format), string(payload), []string{*file}, false)
	fail(err, "record attestation")
	fmt.Printf("Recorded %s attestation (compliant=%v): %s\n", format, result.Compliant, respBody)
}

// handleAttestFetch fetches platform-native SLSA provenance/attestations
// (GitHub Artifact Attestations, GitLab Attestations) for a built artifact
// using the configured git-provider token, and records them onto the trail.
func handleAttestFetch(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("attest fetch", flag.ExitOnError)
	trailID := cmd.String("trail", "", "Trail UUID")
	artSHA := cmd.String("artifact-sha", "", "Artifact SHA256 (hex, required)")
	provider := cmd.String("provider", "", "github | gitlab (optional; inferred from the trail's git host if omitted)")
	repo := cmd.String("repo", "", "owner/repo (github) or group/project (gitlab); defaults to the trail's recorded git repository")
	cmd.Parse(args)

	if *trailID == "" || *artSHA == "" {
		fmt.Println("Error: --trail and --artifact-sha are required\nUsage: fides attest fetch --trail <id> --artifact-sha <hex> [--provider github|gitlab] [--repo <owner/repo>]")
		os.Exit(1)
	}
	post(config, "/api/v1/attest/fetch", map[string]any{
		"trail_id": *trailID, "artifact_sha256": *artSHA, "provider": *provider, "repo": *repo,
	}, "")
}

// handleAttestAuthorship records a code.authorship attestation by parsing the
// git commit trailers (Co-Authored-By, *-Session, Reviewed-by) to determine
// whether a change was authored by a human or an AI agent, and by whom it was
// reviewed. AI-authored changes without a human reviewer are recorded
// non-compliant server-side, so a control requiring code.authorship holds the
// change gate until an agent-generated change has human review.
func handleAttestAuthorship(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("attest authorship", flag.ExitOnError)
	trailID := cmd.String("trail", "", "Trail UUID")
	commit := cmd.String("commit", "HEAD", "git commit to inspect")
	reviewer := cmd.String("reviewer", "", "human reviewer (overrides a Reviewed-by trailer)")
	artSHA := cmd.String("artifact-sha", "", "Artifact SHA256 (optional)")
	name := cmd.String("name", "code-authorship", "Attestation name")
	cmd.Parse(args)

	if *trailID == "" {
		fmt.Println("Error: --trail is required\nUsage: fides attest authorship --trail <id> [--commit <ref>] [--reviewer <name>]")
		os.Exit(1)
	}
	msg, err := gitOutput("log", "-1", "--format=%B", *commit)
	fail(err, "read git commit message")
	sha, err := gitOutput("rev-parse", *commit)
	fail(err, "resolve git commit")

	a := evidence.ParseAuthorship(msg)
	a.Commit = strings.TrimSpace(sha)
	if *reviewer != "" {
		a.HumanReviewer = *reviewer
	}
	payload, _ := json.Marshal(a)

	respBody, err := uploadMultipart(config, *trailID, *artSHA, *name, "code.authorship", string(payload), nil, false)
	fail(err, "record attestation")
	fmt.Printf("Recorded code.authorship attestation (author_kind=%s, reviewer=%q, compliant=%v): %s\n",
		a.AuthorKind, a.HumanReviewer, a.Compliant(), respBody)
}

func uploadMultipart(config CLIConfig, trailID, artifactSHA, name, typeName, payload string, filePaths []string, isEncrypted bool) (string, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// A field that silently fails to write uploads an attestation that
	// says something other than what was recorded.
	if err := writer.WriteField("trail_id", trailID); err != nil {
		fail(err, "build attestation upload")
	}
	if err := writer.WriteField("artifact_sha256", artifactSHA); err != nil {
		fail(err, "build attestation upload")
	}
	if err := writer.WriteField("name", name); err != nil {
		fail(err, "build attestation upload")
	}
	if err := writer.WriteField("type_name", typeName); err != nil {
		fail(err, "build attestation upload")
	}
	if err := writer.WriteField("payload", payload); err != nil {
		fail(err, "build attestation upload")
	}
	if isEncrypted {
		if err := writer.WriteField("encrypted", "true"); err != nil {
			fail(err, "build attestation upload")
		}
	} else {
		if err := writer.WriteField("encrypted", "false"); err != nil {
			fail(err, "build attestation upload")
		}
	}

	for _, path := range filePaths {
		file, err := os.Open(path) // #nosec G304 G703 -- CLI opens a user-specified attachment by design
		if err != nil {
			return "", fmt.Errorf("failed to open attachment: %w", err)
		}
		defer file.Close()

		part, err := writer.CreateFormFile("attachments", filepath.Base(path))
		if err != nil {
			return "", fmt.Errorf("failed to write multipart header: %w", err)
		}

		if _, err := io.Copy(part, file); err != nil {
			return "", fmt.Errorf("failed to copy file content: %w", err)
		}
	}

	if err := writer.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", config.ServerURL+"/api/v1/attestations", body) // #nosec G704 -- request targets the operator-configured Fides server (FIDES_SERVER_URL)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}

	resp, err := httpClient.Do(req) // #nosec G704 -- request targets the operator-configured Fides server (FIDES_SERVER_URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("server returned error code: %d, body: %s", resp.StatusCode, string(respBytes))
	}

	return string(respBytes), nil
}
