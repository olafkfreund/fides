package main

import (
	"encoding/json"
	"flag"
	"fmt"
	neturl "net/url"
	"os"
	"strconv"
	"strings"

	"fides/pkg/crypto"
	"fides/pkg/modelprovenance"
)

// fides model register|attest|inference-log|versions|timeline
//
// EU AI Act model-provenance record-keeping, layered thinly on top of the
// existing flow/trail/attestation engine: a model version is a Trail, and
// training/eval evidence plus inference/decision events are Attestations of
// type modelprovenance.AttestationType on that trail. See pkg/modelprovenance
// for the payload mapping.
func handleModel(config CLIConfig, args []string) {
	if len(args) < 1 {
		printModelUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "register":
		handleModelRegister(config, args[1:])
	case "attest":
		handleModelAttest(config, args[1:])
	case "inference-log":
		handleModelInferenceLog(config, args[1:])
	case "versions":
		handleModelVersions(config, args[1:])
	case "timeline":
		handleModelTimeline(config, args[1:])
	default:
		printModelUsage()
		os.Exit(1)
	}
}

func printModelUsage() {
	fmt.Println("Usage: fides model <register|attest|inference-log|versions|timeline> [arguments]")
	fmt.Println("  register       Register a model version (--flow --version [--repository --commit --branch --framework --risk-category --purpose --tags])")
	fmt.Println("  attest         Record training/eval/audit evidence (--trail --kind [--summary --findings --metadata --compliant --attachments --encrypt])")
	fmt.Println("  inference-log  Record an inference/decision event (--trail --input-hash --decision [--output-hash --confidence --actor --metadata])")
	fmt.Println("  versions       List a model's registered versions (--flow <id>)")
	fmt.Println("  timeline       List a model version's evidence + inference/decision events (--trail <id>)")
}

// fides model register --flow <id> --version <v> [--repository --commit --branch --framework --risk-category --purpose --tags k=v,k2=v2]
func handleModelRegister(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("model register", flag.ExitOnError)
	flowID := cmd.String("flow", "", "Flow UUID representing the model")
	version := cmd.String("version", "", "Model version (trail name), e.g. v1.4.0 or a training-run ID")
	repo := cmd.String("repository", "", "Training-code repository URL")
	commit := cmd.String("commit", "", "Training-code commit SHA")
	branch := cmd.String("branch", "", "Training-code branch")
	framework := cmd.String("framework", "", "Model framework, e.g. pytorch, sklearn")
	riskCategory := cmd.String("risk-category", "", "EU AI Act risk tier: unacceptable|high|limited|minimal")
	purpose := cmd.String("purpose", "", "Intended purpose statement (Art. 13)")
	tags := cmd.String("tags", "", "Comma-separated key=value tags")
	cmd.Parse(args)

	if *flowID == "" || *version == "" {
		fmt.Println("Error: --flow and --version are required")
		cmd.Usage()
		os.Exit(1)
	}

	tagMap, err := parseKV(*tags)
	if err != nil {
		fmt.Printf("Failed to parse --tags: %v\n", err)
		os.Exit(1)
	}

	payload, err := modelprovenance.TrailPayload(modelprovenance.ModelVersion{
		FlowID:          *flowID,
		Version:         *version,
		Repository:      *repo,
		Commit:          *commit,
		Branch:          *branch,
		Framework:       *framework,
		RiskCategory:    *riskCategory,
		IntendedPurpose: *purpose,
		Tags:            tagMap,
	})
	if err != nil {
		fmt.Printf("Failed to build model version: %v\n", err)
		os.Exit(1)
	}

	respBody, err := postRequest(config, "/api/v1/trails", payload)
	if err != nil {
		fmt.Printf("Failed to register model version: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully registered model version: %s\n", respBody)
}

// fides model attest --trail <id> --kind <training-data|evaluation|bias-audit|...> [--summary --findings --metadata --compliant --name --artifact-sha --attachments --encrypt]
func handleModelAttest(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("model attest", flag.ExitOnError)
	trailID := cmd.String("trail", "", "Model version (trail) UUID")
	kind := cmd.String("kind", "", "Evidence kind, e.g. training-data, evaluation, bias-audit")
	name := cmd.String("name", "", "Attestation name (defaults to --kind)")
	artSHA := cmd.String("artifact-sha", "", "Artifact SHA256 (optional)")
	summary := cmd.String("summary", "", "JSON object string, or path to a .json file, with evidence metrics")
	metadata := cmd.String("metadata", "", "JSON object string, or path to a .json file, with additional metadata")
	findings := cmd.String("findings", "", "Comma-separated list of findings")
	compliant := cmd.Bool("compliant", false, "Mark this evidence as compliant")
	attachments := cmd.String("attachments", "", "Comma-separated list of evidence file attachments")
	encryptFlag := cmd.Bool("encrypt", false, "Encrypt the attestation payload using FIDES_ENCRYPTION_KEY")
	cmd.Parse(args)

	if *trailID == "" || *kind == "" {
		fmt.Println("Error: --trail and --kind are required")
		cmd.Usage()
		os.Exit(1)
	}

	summaryMap, err := parseJSONObject(*summary)
	if err != nil {
		fmt.Printf("Failed to parse --summary: %v\n", err)
		os.Exit(1)
	}
	metadataMap, err := parseJSONObject(*metadata)
	if err != nil {
		fmt.Printf("Failed to parse --metadata: %v\n", err)
		os.Exit(1)
	}
	var findingsList []string
	if *findings != "" {
		findingsList = strings.Split(*findings, ",")
	}

	rawPayload, err := modelprovenance.EvidencePayload(modelprovenance.Evidence{
		Kind:      *kind,
		Compliant: *compliant,
		Summary:   summaryMap,
		Findings:  findingsList,
		Metadata:  metadataMap,
	})
	if err != nil {
		fmt.Printf("Failed to build evidence payload: %v\n", err)
		os.Exit(1)
	}

	attestationName := *name
	if attestationName == "" {
		attestationName = *kind
	}

	var isEncrypted bool
	if *encryptFlag {
		rawPayload, isEncrypted, err = encryptPayload(rawPayload)
		if err != nil {
			fmt.Printf("Failed to encrypt payload: %v\n", err)
			os.Exit(1)
		}
	}

	var files []string
	if *attachments != "" {
		files = strings.Split(*attachments, ",")
	}

	respBody, err := uploadMultipart(config, *trailID, *artSHA, attestationName, modelprovenance.AttestationType, rawPayload, files, isEncrypted)
	if err != nil {
		fmt.Printf("Failed to record model evidence: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully recorded %s evidence (compliant=%v): %s\n", *kind, *compliant, respBody)
}

// fides model inference-log --trail <id> --input-hash <sha256> --decision <string> [--output-hash --confidence --actor --metadata --name]
func handleModelInferenceLog(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("model inference-log", flag.ExitOnError)
	trailID := cmd.String("trail", "", "Model version (trail) UUID")
	inputHash := cmd.String("input-hash", "", "SHA256 of the inference input")
	inputFile := cmd.String("input-file", "", "Path to a local file to hash as the inference input (alternative to --input-hash)")
	outputHash := cmd.String("output-hash", "", "SHA256 of the inference output/result (optional)")
	outputFile := cmd.String("output-file", "", "Path to a local file to hash as the inference output (alternative to --output-hash)")
	decision := cmd.String("decision", "", "The decision or result produced")
	confidenceStr := cmd.String("confidence", "", "Confidence score between 0 and 1 (optional)")
	actor := cmd.String("actor", "", "Human reviewer, if any (Art. 14 human oversight)")
	metadata := cmd.String("metadata", "", "JSON object string, or path to a .json file, with additional metadata")
	name := cmd.String("name", modelprovenance.KindInference, "Attestation name")
	cmd.Parse(args)

	if *trailID == "" || *decision == "" {
		fmt.Println("Error: --trail and --decision are required")
		cmd.Usage()
		os.Exit(1)
	}
	if *inputHash == "" && *inputFile == "" {
		fmt.Println("Error: --input-hash or --input-file is required")
		cmd.Usage()
		os.Exit(1)
	}

	resolvedInputHash := *inputHash
	if *inputFile != "" {
		h, err := hashFile(*inputFile)
		if err != nil {
			fmt.Printf("Failed to hash --input-file: %v\n", err)
			os.Exit(1)
		}
		resolvedInputHash = h
	}
	resolvedOutputHash := *outputHash
	if *outputFile != "" {
		h, err := hashFile(*outputFile)
		if err != nil {
			fmt.Printf("Failed to hash --output-file: %v\n", err)
			os.Exit(1)
		}
		resolvedOutputHash = h
	}

	var confidence *float64
	if *confidenceStr != "" {
		v, err := strconv.ParseFloat(*confidenceStr, 64)
		if err != nil {
			fmt.Printf("Failed to parse --confidence: %v\n", err)
			os.Exit(1)
		}
		confidence = &v
	}

	metadataMap, err := parseJSONObject(*metadata)
	if err != nil {
		fmt.Printf("Failed to parse --metadata: %v\n", err)
		os.Exit(1)
	}

	rawPayload, err := modelprovenance.InferenceLogPayload(modelprovenance.InferenceEvent{
		InputHash:  resolvedInputHash,
		OutputHash: resolvedOutputHash,
		Decision:   *decision,
		Confidence: confidence,
		Actor:      *actor,
		Metadata:   metadataMap,
	})
	if err != nil {
		fmt.Printf("Failed to build inference log payload: %v\n", err)
		os.Exit(1)
	}

	respBody, err := uploadMultipart(config, *trailID, "", *name, modelprovenance.AttestationType, rawPayload, nil, false)
	if err != nil {
		fmt.Printf("Failed to record inference log: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully recorded inference/decision event: %s\n", respBody)
}

// fides model versions --flow <id>
func handleModelVersions(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("model versions", flag.ExitOnError)
	flowID := cmd.String("flow", "", "Flow UUID representing the model")
	cmd.Parse(args)
	if *flowID == "" {
		fmt.Println("Error: --flow is required")
		cmd.Usage()
		os.Exit(1)
	}
	body, err := getRequest(config, "/api/v1/flows/"+*flowID+"/trails")
	fail(err, "list model versions")
	fmt.Println(body)
}

// fides model timeline --trail <id>
func handleModelTimeline(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("model timeline", flag.ExitOnError)
	trailID := cmd.String("trail", "", "Model version (trail) UUID")
	cmd.Parse(args)
	if *trailID == "" {
		fmt.Println("Error: --trail is required")
		cmd.Usage()
		os.Exit(1)
	}
	q := neturl.Values{}
	q.Set("type", modelprovenance.AttestationType)
	q.Set("trail", *trailID)
	body, err := getRequest(config, "/api/v1/search/attestations?"+q.Encode())
	fail(err, "list model timeline")
	fmt.Println(body)
}

// parseKV parses a comma-separated key=value list, as used by --tags flags
// throughout the CLI.
func parseKV(s string) (map[string]string, error) {
	if s == "" {
		return nil, nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 || kv[0] == "" {
			return nil, fmt.Errorf("invalid key=value pair %q", pair)
		}
		out[kv[0]] = kv[1]
	}
	return out, nil
}

// parseJSONObject accepts either a raw JSON object string or a path to a
// .json file (mirroring how --payload is handled by `fides attest`), and
// returns the decoded object. An empty input returns a nil map.
func parseJSONObject(s string) (map[string]any, error) {
	if s == "" {
		return nil, nil
	}
	raw := s
	if strings.HasSuffix(s, ".json") {
		content, err := os.ReadFile(s) // #nosec G304 -- CLI reads a user-specified file by design
		if err != nil {
			return nil, err
		}
		raw = string(content)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("invalid JSON object: %w", err)
	}
	return m, nil
}

// encryptPayload encrypts payload with FIDES_ENCRYPTION_KEY, mirroring the
// encryption path in `fides attest`.
func encryptPayload(payload string) (string, bool, error) {
	encryptionKeyEnv := os.Getenv("FIDES_ENCRYPTION_KEY")
	if encryptionKeyEnv == "" {
		return "", false, fmt.Errorf("encryption requires FIDES_ENCRYPTION_KEY environment variable to be set")
	}
	key, err := crypto.DeriveKey(encryptionKeyEnv)
	if err != nil {
		return "", false, fmt.Errorf("derive encryption key: %w", err)
	}
	encrypted, err := crypto.Encrypt([]byte(payload), key)
	if err != nil {
		return "", false, fmt.Errorf("encrypt payload: %w", err)
	}
	return encrypted, true, nil
}
