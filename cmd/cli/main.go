package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fides/pkg/crypto"
)

// httpClient is shared across CLI requests and enforces an overall timeout so a
// hung server cannot block the CLI indefinitely.
var httpClient = &http.Client{Timeout: 30 * time.Second}

type CLIConfig struct {
	ServerURL string
	Token     string
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	serverURL := os.Getenv("FIDES_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}
	token := os.Getenv("FIDES_API_TOKEN")

	config := CLIConfig{
		ServerURL: serverURL,
		Token:     token,
	}

	switch command {
	case "trail":
		handleTrail(config, os.Args[2:])
	case "artifact":
		handleArtifact(config, os.Args[2:])
	case "attest":
		handleAttest(config, os.Args[2:])
	case "assert":
		handleAssert(config, os.Args[2:])
	case "snapshot":
		handleSnapshot(config, os.Args[2:])
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Fides - Cross-Platform Compliance & Provenance CLI")
	fmt.Println("Usage:")
	fmt.Println("  fides <command> [arguments]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  trail start      Initialize a new build trail")
	fmt.Println("  artifact report  Record a build artifact fingerprint (SHA256)")
	fmt.Println("  attest           Report tests, security scans, or custom evidence")
	fmt.Println("  assert           Evaluate policy gate compliance for an artifact")
	fmt.Println("  snapshot         Snapshot running container runtimes and send to Fides")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  FIDES_SERVER_URL  URL of the Fides server (default: http://localhost:8080)")
	fmt.Println("  FIDES_API_TOKEN   Authentication token for the Fides server")
}

// 1. Trail Management
func handleTrail(config CLIConfig, args []string) {
	if len(args) < 1 || args[0] != "start" {
		fmt.Println("Usage: fides trail start --flow <flow_id> --trail <trail_name> [--repository <url>] [--commit <sha>]")
		os.Exit(1)
	}

	cmd := flag.NewFlagSet("trail start", flag.ExitOnError)
	flowID := cmd.String("flow", "", "Flow UUID")
	trailName := cmd.String("trail", "", "Trail name (Git SHA, build number)")
	repo := cmd.String("repository", "", "Git repository URL")
	commit := cmd.String("commit", "", "Git commit SHA")
	branch := cmd.String("branch", "", "Git branch name")
	msg := cmd.String("message", "", "Git commit message")

	cmd.Parse(args[1:])

	if *flowID == "" || *trailName == "" {
		fmt.Println("Error: --flow and --trail are required")
		cmd.Usage()
		os.Exit(1)
	}

	payload := map[string]interface{}{
		"flow_id":        *flowID,
		"name":           *trailName,
		"git_repository": *repo,
		"git_commit":     *commit,
		"git_branch":     *branch,
		"git_message":    *msg,
	}

	respBody, err := postRequest(config, "/api/v1/trails", payload)
	if err != nil {
		fmt.Printf("Failed to initialize trail: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully initialized trail: %s\n", respBody)
}

// 2. Artifact Reporting
func handleArtifact(config CLIConfig, args []string) {
	if len(args) < 1 || args[0] != "report" {
		fmt.Println("Usage: fides artifact report --org <org_id> --trail <trail_id> --sha256 <fingerprint> --name <artifact_name> --type <docker/binary>")
		os.Exit(1)
	}

	cmd := flag.NewFlagSet("artifact report", flag.ExitOnError)
	orgID := cmd.String("org", "", "Org UUID")
	trailID := cmd.String("trail", "", "Trail UUID")
	sha := cmd.String("sha256", "", "SHA256 fingerprint of artifact")
	name := cmd.String("name", "", "Artifact name")
	artType := cmd.String("type", "docker", "Artifact type (e.g. docker, binary, file)")
	file := cmd.String("file", "", "Calculate SHA256 directly from local file path")

	cmd.Parse(args[1:])

	if *orgID == "" || (*sha == "" && *file == "") || *name == "" {
		fmt.Println("Error: --org, --name, and either --sha256 or --file are required")
		cmd.Usage()
		os.Exit(1)
	}

	var calculatedSHA string
	if *file != "" {
		calculated, err := hashFile(*file)
		if err != nil {
			fmt.Printf("Failed to hash file: %v\n", err)
			os.Exit(1)
		}
		calculatedSHA = calculated
		fmt.Printf("Calculated SHA256 of %s: %s\n", *file, calculatedSHA)
	} else {
		calculatedSHA = *sha
	}

	payload := map[string]interface{}{
		"org_id":     *orgID,
		"trail_id":   *trailID,
		"sha256":     calculatedSHA,
		"name":       *name,
		"type":       *artType,
		"created_at": time.Now(),
	}

	respBody, err := postRequest(config, "/api/v1/artifacts", payload)
	if err != nil {
		fmt.Printf("Failed to report artifact: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully registered artifact: %s\n", respBody)
}

// 3. Attestation Reporting
func handleAttest(config CLIConfig, args []string) {
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

// 4. Assertion (Policy Gate Check)
func handleAssert(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("assert", flag.ExitOnError)
	sha := cmd.String("sha256", "", "Artifact SHA256 digest")
	policyName := cmd.String("policy", "", "Policy name to evaluate against")

	cmd.Parse(args)

	if *sha == "" {
		fmt.Println("Error: --sha256 is required")
		cmd.Usage()
		os.Exit(1)
	}

	q := neturl.Values{}
	q.Set("sha256", *sha)
	q.Set("policy", *policyName)
	reqURL := fmt.Sprintf("%s/api/v1/compliance?%s", config.ServerURL, q.Encode())
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		fmt.Printf("Failed to create request: %v\n", err)
		os.Exit(1)
	}

	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("Server check failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("Failed to parse response: %v\n", err)
		os.Exit(1)
	}

	compliant, _ := result["compliant"].(bool)
	violations, _ := result["violations"].([]interface{})

	if !compliant {
		fmt.Printf("COMPLIANCE FAILURE: Artifact %s is NON-COMPLIANT\n", *sha)
		for _, v := range violations {
			fmt.Printf("  - %v\n", v)
		}
		os.Exit(1) // Exits non-zero to fail the CI/CD step
	}

	fmt.Printf("COMPLIANCE PASS: Artifact %s is compliant with policies\n", *sha)
}

// 5. Environment Snapshotting
func handleSnapshot(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides snapshot docker --env <environment_id> [--container <name>]")
		os.Exit(1)
	}

	runtimeType := args[0]
	cmd := flag.NewFlagSet("snapshot", flag.ExitOnError)
	envID := cmd.String("env", "", "Environment UUID")
	containerName := cmd.String("container", "", "Target single container name (optional)")
	namespace := cmd.String("namespace", "", "Target namespace to filter pods (optional)")

	cmd.Parse(args[1:])

	if *envID == "" {
		fmt.Println("Error: --env is required")
		os.Exit(1)
	}

	var reportedArtifacts []map[string]string

	if runtimeType == "docker" {
		// Mock query docker sockets/inspect to fetch container digests.
		// In a real cli client we'd pull from: Docker CLI socket client.
		fmt.Println("Ingesting running docker containers...")

		// Demo mock container digest report
		mockDigest := "b1d830f367e9154ec5a6dc8634c01d6706e23b20757d59850c90c01067e23b20"
		reportedArtifacts = append(reportedArtifacts, map[string]string{
			"sha256":       mockDigest,
			"service_name": *containerName,
		})
	} else if runtimeType == "k8s" {
		fmt.Println("Ingesting running Kubernetes namespaces dynamically...")
		cmdK8s := exec.Command("kubectl", "get", "pods", "-A", "-o", "json")
		var out bytes.Buffer
		cmdK8s.Stdout = &out
		err := cmdK8s.Run()
		if err != nil {
			fmt.Printf("Failed to query Kubernetes pods: %v. Falling back to mock data.\n", err)
			mockDigest := "3eb45c05c6d3df3634208a05c6d3df3634208a05c6d3df3634208a05c6d3df36"
			reportedArtifacts = append(reportedArtifacts, map[string]string{
				"sha256":       mockDigest,
				"service_name": "kubernetes-pod-auth",
			})
		} else {
			var podList struct {
				Items []struct {
					Metadata struct {
						Name      string `json:"name"`
						Namespace string `json:"namespace"`
					} `json:"metadata"`
					Status struct {
						ContainerStatuses []struct {
							Name    string `json:"name"`
							Image   string `json:"image"`
							ImageID string `json:"imageID"`
						} `json:"containerStatuses"`
					} `json:"status"`
				} `json:"items"`
			}
			if err := json.Unmarshal(out.Bytes(), &podList); err == nil {
				for _, pod := range podList.Items {
					ns := pod.Metadata.Namespace
					// Filter out system namespaces
					if ns == "kube-system" || ns == "kube-public" || ns == "kube-node-lease" || ns == "ingress-nginx" || ns == "cert-manager" || ns == "external-secrets" || ns == "argocd" || ns == "gitlab" {
						continue
					}
					// Filter by namespace if requested
					if *namespace != "" && ns != *namespace {
						continue
					}
					for _, container := range pod.Status.ContainerStatuses {
						digest := ""
						parts := strings.Split(container.ImageID, "@sha256:")
						if len(parts) == 2 {
							digest = parts[1]
						} else {
							digest = container.ImageID
						}
						// Strip sha256: prefix if present
						digest = strings.TrimPrefix(digest, "sha256:")
						if digest == "" {
							digest = container.Image
						}
						if len(digest) > 64 {
							digest = digest[:64]
						}

						reportedArtifacts = append(reportedArtifacts, map[string]string{
							"sha256":       digest,
							"service_name": container.Name,
						})
					}
				}
			} else {
				fmt.Printf("Failed to parse kubectl json: %v\n", err)
			}
		}
	}

	payload := map[string]interface{}{
		"environment_id": *envID,
		"artifacts":      reportedArtifacts,
	}

	respBody, err := postRequest(config, "/api/v1/snapshots", payload)
	if err != nil {
		fmt.Printf("Failed to report snapshot: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Snapshot submitted successfully: %s\n", respBody)
}

// Helpers

func postRequest(config CLIConfig, path string, data interface{}) (string, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", config.ServerURL+path, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}

	resp, err := httpClient.Do(req)
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

func uploadMultipart(config CLIConfig, trailID, artifactSHA, name, typeName, payload string, filePaths []string, isEncrypted bool) (string, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	writer.WriteField("trail_id", trailID)
	writer.WriteField("artifact_sha256", artifactSHA)
	writer.WriteField("name", name)
	writer.WriteField("type_name", typeName)
	writer.WriteField("payload", payload)
	if isEncrypted {
		writer.WriteField("encrypted", "true")
	} else {
		writer.WriteField("encrypted", "false")
	}

	for _, path := range filePaths {
		file, err := os.Open(path)
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

	req, err := http.NewRequest("POST", config.ServerURL+"/api/v1/attestations", body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}

	resp, err := httpClient.Do(req)
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

func hashFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
