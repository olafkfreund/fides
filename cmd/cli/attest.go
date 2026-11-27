package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

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
	recordingFlag(cmd, &config)
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

	if config.FailOpen && !json.Valid([]byte(rawPayload)) {
		fail(fmt.Errorf("invalid attestation payload JSON"), "record attestation")
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
	respBody, err := uploadMultipart(config, *trailID, *artSHA, *name, *typeName, rawPayload, attachmentPaths(*attachments), isEncrypted)
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
	recordingFlag(cmd, &config)
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

	respBody, err := uploadMultipart(config, *trailID, *artSHA, *name, evidenceTypeName(format), string(payload), []attestationAttachment{{path: *file, data: data}}, false)
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
	recordingFlag(cmd, &config)
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

type attestationAttachment struct {
	path string
	data []byte
}

func attachmentPaths(paths string) []attestationAttachment {
	var files []attestationAttachment
	if paths != "" {
		for _, path := range strings.Split(paths, ",") {
			files = append(files, attestationAttachment{path: path})
		}
	}
	return files
}

func (a attestationAttachment) writeTo(part io.Writer, limit int64) error {
	if a.data != nil {
		if int64(len(a.data)) > limit {
			return fmt.Errorf("attestation body exceeds the server size limit")
		}
		_, err := part.Write(a.data)
		return err
	}
	file, err := os.Open(a.path) // #nosec G304 G703 -- CLI opens a user-specified attachment by design
	if err != nil {
		return fmt.Errorf("failed to open attachment: %w", err)
	}
	defer file.Close()
	n, err := io.Copy(part, io.LimitReader(file, limit+1))
	if err != nil {
		return fmt.Errorf("failed to copy file content: %w", err)
	}
	if n > limit {
		return fmt.Errorf("attestation body exceeds the server size limit")
	}
	return nil
}

func uploadMultipart(config CLIConfig, trailID, artifactSHA, name, typeName, payload string, files []attestationAttachment, isEncrypted bool) (string, error) {
	if config.FailOpen && (utf8.RuneCountInString(name) > 100 || utf8.RuneCountInString(typeName) > 100 ||
		(artifactSHA != "" && !isSHA256Hex(artifactSHA))) {
		return "", fmt.Errorf("invalid attestation name, type, or artifact SHA256")
	}
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormField("trail_id")
	if err != nil {
		return "", err
	}
	entry := recording{Path: attestationRecord, TrailOffset: body.Len(), ArtifactSHA: artifactSHA}
	if _, err := io.WriteString(part, trailID); err != nil {
		return "", err
	}
	for _, field := range [][2]string{
		{"artifact_sha256", artifactSHA},
		{"name", name},
		{"type_name", typeName},
		{"payload", payload},
		{"encrypted", strconv.FormatBool(isEncrypted)},
	} {
		if err := writer.WriteField(field[0], field[1]); err != nil {
			return "", err
		}
	}

	for _, file := range files {
		part, err := writer.CreateFormFile("attachments", filepath.Base(file.path))
		if err != nil {
			return "", fmt.Errorf("failed to write multipart header: %w", err)
		}
		if err := file.writeTo(part, max(int64(maxRecordingBody-body.Len()), 0)); err != nil {
			return "", err
		}
	}

	if err := writer.Close(); err != nil {
		return "", err
	}

	entry.ContentType = writer.FormDataContentType()
	return record(config, entry, body.Bytes(), trailID)
}
