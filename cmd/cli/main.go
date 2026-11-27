package main

import (
	"fmt"
	"os"

	"fides/pkg/version"
)

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
	case "verify-image":
		handleVerifyImage(config, os.Args[2:])
	case "snapshot":
		handleSnapshot(config, os.Args[2:])
	case "sbom":
		handleSBOM(config, os.Args[2:])
	case "vuln":
		handleVuln(config, os.Args[2:])
	case "servicenow":
		handleServiceNow(config, os.Args[2:])
	case "git-provider":
		handleGitProvider(config, os.Args[2:])
	case "webhook":
		handleWebhook(config, os.Args[2:])
	case "user":
		handleUser(config, os.Args[2:])
	case "verify-chain":
		handleVerifyChain(config, os.Args[2:])
	case "anchor":
		handleAnchor(config, os.Args[2:])
	case "service-account":
		handleServiceAccount(config, os.Args[2:])
	case "allowlist":
		handleAllowlist(config, os.Args[2:])
	case "remediation":
		handleRemediation(config, os.Args[2:])
	case "search":
		handleSearch(config, os.Args[2:])
	case "impact":
		handleImpact(config, os.Args[2:])
	case "vex":
		handleVEX(config, os.Args[2:])
	case "audit":
		handleAudit(config, os.Args[2:])
	case "policy":
		handlePolicy(config, os.Args[2:])
	case "logical-env":
		handleLogicalEnv(config, os.Args[2:])
	case "metrics":
		handleMetrics(config, os.Args[2:])
	case "control":
		handleControl(config, os.Args[2:])
	case "risk":
		body, err := getRequest(config, "/api/v1/risk-register")
		fail(err, "risk register")
		fmt.Println(body)
	case "exception":
		handleException(config, os.Args[2:])
	case "sdlc":
		body, err := getRequest(config, "/api/v1/sdlc")
		fail(err, "sdlc view")
		fmt.Println(body)
	case "service":
		handleService(config, os.Args[2:])
	case "training":
		handleTraining(config, os.Args[2:])
	case "audit-pack":
		body, err := getRequest(config, "/api/v1/audit-pack")
		fail(err, "audit pack")
		fmt.Println(body)
	case "flow":
		handleFlow(config, os.Args[2:])
	case "flag":
		handleFlagChange(config, os.Args[2:])
	case "model":
		handleModel(config, os.Args[2:])
	case "change-gate":
		handleChangeGate(config, os.Args[2:])
	case "report":
		handleReport(config, os.Args[2:])
	case "approve":
		handleApprove(config, os.Args[2:])
	case "slack":
		handleSlack(config, os.Args[2:])
	case "dashboard":
		runDashboard(config, os.Args[2:])
	case "env":
		sub := ""
		if len(os.Args) > 2 {
			sub = os.Args[2]
		}
		switch sub {
		case "create":
			handleEnvCreate(config, os.Args[3:])
		case "list":
			handleEnvList(config, os.Args[3:])
		case "diff":
			handleEnvDiff(config, os.Args[3:])
		case "verify":
			handleEnvVerify(config, os.Args[3:])
		case "archive":
			handleEnvArchive(config, os.Args[3:], true)
		case "unarchive":
			handleEnvArchive(config, os.Args[3:], false)
		default:
			fmt.Println("Usage: fides env <create|list|diff|verify|archive|unarchive> ...")
			os.Exit(1)
		}
	case "version", "--version", "-v":
		fmt.Println("fides", version.String())
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
	fmt.Println("  attest           Report custom evidence, a junit/snyk/trivy/slsa/sbom report, or ingest GitHub/GitLab")
	fmt.Println("                   native provenance (fides attest junit --file ... | fides attest fetch --provider github ...)")
	fmt.Println("  assert           Check compliance by artifact digest (--sha256)")
	fmt.Println("  verify-image     Verify a container image's cosign signature (deploy gate; exits 2 on failure)")
	fmt.Println("  snapshot         Snapshot a runtime (docker|k8s|ecs|lambda) and send to Fides")
	fmt.Println("  servicenow       Configure ServiceNow (config|get|change-check|anchor-deployment)")
	fmt.Println("  git-provider     Configure a GitHub/GitLab provider (config)")
	fmt.Println("  webhook          Configure an outbound signed webhook (config)")
	fmt.Println("  user             Manage users (set-password)")
	fmt.Println("  verify-chain     Verify a trail's tamper-evidence attestation chain (incl. external RFC3161 anchor)")
	fmt.Println("  anchor           Anchor a trail's chain head to an external RFC3161 timestamp authority (--trail [--tsa])")
	fmt.Println("  service-account  Manage service accounts & API keys (create|list|issue-key|revoke-key)")
	fmt.Println("  allowlist        Approve artifacts for an environment (add|list|check|remove)")
	fmt.Println("  remediation      Policy-driven auto-remediation (propose|list|get|approve|reject|apply)")
	fmt.Println("  policy           Manage/check environment policies (add|list|check --env <id>)")
	fmt.Println("  logical-env      Aggregate physical environments (create|list|add-member|state)")
	fmt.Println("  metrics          DORA-style delivery metrics (--days N)")
	fmt.Println("  control          Governance controls + coverage (add|list|coverage|import|enforce|archive|unarchive)")
	fmt.Println("  flow             Flows (list | trails --flow <id> | artifacts --flow <id>)")
	fmt.Println("  flag             Record a feature-flag change as governed evidence (flag record --flag-key --env --from --to)")
	fmt.Println("  model            EU AI Act model provenance (register|attest|inference-log|versions|timeline)")
	fmt.Println("  change-gate      Evidence-backed approval verdict + risk score (--trail <id>; exits 2 on hold)")
	fmt.Println("  policy           Policies (create|delete|generate | add|list|check --env <id>)")
	fmt.Println("  metrics          DORA metrics (--days N), deployment-frequency (--weeks N), or")
	fmt.Println("                   compliance-correlation (--days N): DORA vs risk score & control coverage")
	fmt.Println("  audit            Download a trail's audit package ZIP (--trail <id> [--output])")
	fmt.Println("  search           Search artifacts/attestations/components (search artifacts|attestations|components ...)")
	fmt.Println("  impact           Show artifacts + running environments affected by a CVE (--cve <CVE-ID>)")
	fmt.Println("  vex              Record a VEX statement to suppress/annotate a CVE (--cve --status [--product --justification])")
	fmt.Println("  env diff         Diff two environment snapshots (--env <id> [--from --to] [--reevaluate-change CHGxxxx])")
	fmt.Println("  env verify       Runtime MCP compliance check (--env --server --tool --rule ...)")
	fmt.Println("  env archive      Retire an environment from control coverage (--env <id>); unarchive restores it")
	fmt.Println("  dashboard        Interactive terminal dashboard of live server stats (TUI)")
	fmt.Println("  sbom diff        Diff two local SBOM files (added/removed/changed components) [--json]")
	fmt.Println("  vuln diff        Diff two scan reports; gate on NEW CVEs (--format trivy|snyk|sarif) [--fail-on-new]")
	fmt.Println("  version          Print the fides CLI version")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  FIDES_SERVER_URL  URL of the Fides server (default: http://localhost:8080)")
	fmt.Println("  FIDES_API_TOKEN   Authentication token for the Fides server")
}
