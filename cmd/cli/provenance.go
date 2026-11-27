package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	neturl "net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"fides/pkg/cliprogress"
	"fides/pkg/exitcode"
)

func handleTrail(config CLIConfig, args []string) {
	if len(args) < 1 || args[0] != "start" {
		fmt.Println("Usage: fides trail start --flow <flow_id> --trail <trail_name> [--repository <url>] [--commit <sha>] [--committer <email>]")
		os.Exit(1)
	}

	cmd := flag.NewFlagSet("trail start", flag.ExitOnError)
	flowID := cmd.String("flow", "", "Flow UUID")
	trailName := cmd.String("trail", "", "Trail name (Git SHA, build number)")
	repo := cmd.String("repository", "", "Git repository URL")
	commit := cmd.String("commit", "", "Git commit SHA")
	branch := cmd.String("branch", "", "Git branch name")
	msg := cmd.String("message", "", "Git commit message")
	committer := cmd.String("committer", "", "Committer identity (email/username) from commit metadata — recorded as a trail tag and used by the segregation-of-duties attestation")
	committedAt := cmd.String("committed-at", "", "Commit timestamp (RFC3339) for true code-to-prod lead time; auto-derived from git when --commit is set")
	quiet := cmd.Bool("quiet", false, "print only the created trail's id (handy for: TRAIL_ID=$(fides trail start ... -q))")
	cmd.BoolVar(quiet, "q", false, "alias for --quiet")

	cmd.Parse(args[1:])

	if *flowID == "" || *trailName == "" {
		fmt.Println("Error: --flow and --trail are required")
		cmd.Usage()
		os.Exit(1)
	}

	// Record the commit timestamp for true code-to-prod lead time. Prefer an
	// explicit --committed-at; otherwise derive it from git when a commit is given
	// (best-effort — silently skipped outside a repo or for an unknown commit).
	committedAtVal := *committedAt
	if committedAtVal == "" && *commit != "" {
		if out, err := gitOutput("show", "-s", "--format=%cI", *commit); err == nil {
			committedAtVal = strings.TrimSpace(out)
		}
	}

	payload := map[string]interface{}{
		"flow_id":          *flowID,
		"name":             *trailName,
		"git_repository":   *repo,
		"git_commit":       *commit,
		"git_branch":       *branch,
		"git_message":      *msg,
		"git_committed_at": committedAtVal,
	}
	if *committer != "" {
		payload["tags"] = map[string]string{"committer": *committer}
	}

	respBody, err := postRequest(config, "/api/v1/trails", payload)
	if err != nil {
		fmt.Printf("Failed to initialize trail: %v\n", err)
		os.Exit(1)
	}

	if *quiet {
		var t struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal([]byte(respBody), &t)
		fmt.Println(t.ID)
		return
	}
	fmt.Printf("Successfully initialized trail: %s\n", respBody)
}

func handleArtifact(config CLIConfig, args []string) {
	if len(args) < 1 || args[0] != "report" {
		fmt.Println("Usage: fides artifact report --trail <trail_id> (--sha256 <fingerprint> | --file <path>) --name <name> [--type docker|binary]")
		os.Exit(1)
	}

	cmd := flag.NewFlagSet("artifact report", flag.ExitOnError)
	// --org is optional and ignored server-side: the tenant is taken from the API
	// token (the server never trusts a body org — H2/IDOR). Kept for compatibility.
	orgID := cmd.String("org", "", "Org UUID (optional; ignored — org comes from the token)")
	trailID := cmd.String("trail", "", "Trail UUID")
	sha := cmd.String("sha256", "", "SHA256 fingerprint of artifact")
	name := cmd.String("name", "", "Artifact name")
	artType := cmd.String("type", "docker", "Artifact type (e.g. docker, binary, file)")
	file := cmd.String("file", "", "Calculate SHA256 directly from local file path")

	cmd.Parse(args[1:])

	if (*sha == "" && *file == "") || *name == "" {
		fmt.Println("Error: --name and either --sha256 or --file are required")
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

// fides flow list | trails --flow <id> | artifacts --flow <id>
func handleFlow(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides flow <list|trails|artifacts> [--flow <id>]")
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		body, err := getList(config, "/api/v1/flows")
		fail(err, "list flows")
		fmt.Println(body)
	case "trails", "artifacts":
		cmd := flag.NewFlagSet("flow "+args[0], flag.ExitOnError)
		flow := cmd.String("flow", "", "flow UUID")
		cmd.Parse(args[1:])
		if *flow == "" {
			fmt.Println("Error: --flow is required")
			os.Exit(1)
		}
		body, err := getList(config, "/api/v1/flows/"+*flow+"/"+args[0])
		fail(err, "list flow "+args[0])
		fmt.Println(body)
	default:
		fmt.Println("Usage: fides flow <list|trails|artifacts> [--flow <id>]")
		os.Exit(1)
	}
}

// fides verify-chain --trail <id>
func handleVerifyChain(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("verify-chain", flag.ExitOnError)
	trailID := cmd.String("trail", "", "trail UUID")
	cmd.Parse(args)
	if *trailID == "" {
		fmt.Println("Usage: fides verify-chain --trail <trail_id>")
		os.Exit(1)
	}
	p := cliprogress.New(os.Stderr, false)
	p.StartStage("Verifying tamper-evidence chain")
	body, err := getRequest(config, "/api/v1/trails/"+*trailID+"/verify-chain")
	if err != nil {
		p.CompleteStage("")
		fail(err, "verify chain")
	}
	p.CompleteStage("Chain checked")
	fmt.Println(body)
	if strings.Contains(body, "\"valid\":false") {
		os.Exit(exitcode.Violation) // so CI fails on a broken chain
	}
}

// handleAnchor timestamps a trail's chain head with an external RFC3161 TSA, so
// verify-chain can later prove the head existed independently of the Fides DB.
func handleAnchor(config CLIConfig, args []string) {
	cmd := flag.NewFlagSet("anchor", flag.ExitOnError)
	trailID := cmd.String("trail", "", "trail UUID")
	tsaURL := cmd.String("tsa", "", "RFC3161 TSA URL (defaults to server's FIDES_TSA_URL)")
	cmd.Parse(args)
	if *trailID == "" {
		fmt.Println("Usage: fides anchor --trail <trail_id> [--tsa <url>]")
		os.Exit(1)
	}
	post(config, "/api/v1/trails/"+*trailID+"/anchor", map[string]any{"tsa_url": *tsaURL}, "")
}

// fides search artifacts|attestations|components
func handleSearch(config CLIConfig, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: fides search <artifacts|attestations|components> [--sha --commit --name | --type --trail --compliant | --purl --artifact --name]")
		os.Exit(1)
	}
	cmd := flag.NewFlagSet("search "+args[0], flag.ExitOnError)
	sha := cmd.String("sha", "", "artifact SHA256 prefix")
	commit := cmd.String("commit", "", "git commit")
	name := cmd.String("name", "", "artifact name (substring), or component name (substring)")
	typ := cmd.String("type", "", "attestation type name")
	trail := cmd.String("trail", "", "trail UUID")
	compliant := cmd.String("compliant", "", "true|false")
	purl := cmd.String("purl", "", "component package URL (purl), exact match")
	artifact := cmd.String("artifact", "", "artifact SHA256, exact match (which deployed artifacts contain this component)")
	cmd.Parse(args[1:])

	q := neturl.Values{}
	var path string
	switch args[0] {
	case "artifacts":
		path = "/api/v1/search/artifacts"
		setIf(q, "sha", *sha)
		setIf(q, "commit", *commit)
		setIf(q, "name", *name)
	case "attestations":
		path = "/api/v1/search/attestations"
		setIf(q, "type", *typ)
		setIf(q, "trail", *trail)
		setIf(q, "compliant", *compliant)
	case "components":
		path = "/api/v1/search/components"
		setIf(q, "purl", *purl)
		setIf(q, "artifact", *artifact)
		setIf(q, "name", *name)
	default:
		fmt.Println("Usage: fides search <artifacts|attestations|components>")
		os.Exit(1)
	}
	body, err := getList(config, path+"?"+q.Encode())
	fail(err, "search")
	fmt.Println(body)
}

// handleFlagChange records a feature-flag change as a flag.changed attestation
// (POST /api/v1/flags/changed), making the change governed evidence.
func handleFlagChange(config CLIConfig, args []string) {
	if len(args) >= 1 && args[0] == "list" {
		cmd := flag.NewFlagSet("flag list", flag.ExitOnError)
		limit := cmd.Int("limit", 100, "max flag changes to list")
		cmd.Parse(args[1:])
		if *limit < 1 || *limit > 1000 {
			*limit = 100
		}
		body, err := getListUpTo(config, fmt.Sprintf("/api/v1/flags/history?limit=%d", min(*limit, 500)), *limit)
		fail(err, "list flag changes")
		fmt.Println(body)
		return
	}
	if len(args) < 1 || args[0] != "record" {
		fmt.Println("Usage: fides flag record --flag-key <key> --env <env> --from <state> --to <state> [--actor <a>] [--source unleash|flagsmith|manual] [--flow <id>]\n       fides flag list [--limit N]")
		os.Exit(1)
	}
	cmd := flag.NewFlagSet("flag record", flag.ExitOnError)
	key := cmd.String("flag-key", "", "feature flag key (required)")
	env := cmd.String("env", "", "environment (e.g. prod)")
	from := cmd.String("from", "", "old state")
	to := cmd.String("to", "", "new state")
	actor := cmd.String("actor", "", "who made the change")
	source := cmd.String("source", "manual", "unleash | flagsmith | manual")
	flowID := cmd.String("flow", "", "flow UUID (optional; defaults to the org's feature-flags flow)")
	cmd.Parse(args[1:])
	if *key == "" {
		fmt.Println("Error: --flag-key is required")
		os.Exit(1)
	}
	post(config, "/api/v1/flags/changed", map[string]any{
		"flag_key": *key, "environment": *env, "old_state": *from, "new_state": *to,
		"actor": *actor, "source": *source, "flow_id": *flowID,
	}, "")
}

// gitOutput runs a git subcommand and returns its trimmed stdout.
func gitOutput(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output() // #nosec G204 -- fixed subcommand; ref is passed as an arg, never a shell string
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func hashFile(filePath string) (string, error) {
	file, err := os.Open(filePath) // #nosec G304 -- CLI hashes a user-specified file by design
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
